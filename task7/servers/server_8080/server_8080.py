#!/usr/bin/env python3

import argparse, socket, time, os

def recv_until_double_crlf(conn, timeout=2.0):
    conn.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data:
            # don't break right away — HTTP body may follow; caller can read Content-Length
            break
    return data

def read_http_body_from_buf(buf, conn):
    # buf contains headers and maybe some body. Try to parse Content-Length and read the rest from conn if needed.
    headers, sep, rest = buf.partition(b"\r\n\r\n")
    headers_text = headers.decode('latin1', errors='replace')
    content_length = 0
    for line in headers_text.splitlines():
        if ':' in line:
            k,v = line.split(':',1)
            if k.strip().lower() == 'content-length':
                try:
                    content_length = int(v.strip())
                except:
                    content_length = 0
    body = rest
    toread = content_length - len(body)
    while toread > 0:
        chunk = conn.recv(min(4096, toread))
        if not chunk: break
        body += chunk
        toread -= len(chunk)
    return headers + b"\r\n\r\n" + body

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--resp1", help="path to file with full HTTP response bytes for the response", required=True)
    ap.add_argument("--resp2", help="key switch 1", required=True)
    ap.add_argument("--resp3", help="key switch 2", required=False)
    ap.add_argument("--resp4", help="path to file with full HTTP response after re-key", required=False)	
    args = ap.parse_args()

    if args.resp1 and os.path.exists(args.resp1):
        resp1 = open(args.resp1,"rb").read()
        print("Using RESP1 from file")
    else:
        print("Resp file is missing")
        return
		
    if args.resp2 and os.path.exists(args.resp2):
        resp2 = open(args.resp2,"rb").read()
        print("Using RESP2 from file")
    else:
        print("Resp file is missing")
        return
		
    if args.resp3 and os.path.exists(args.resp3):
        resp3 = open(args.resp3,"rb").read()
        print("Using RESP3 from file")
    else:
        print("Resp file is missing")
        return
		
    if args.resp4 and os.path.exists(args.resp4):
        resp4 = open(args.resp4,"rb").read()
        print("Using RESP4 from file")
    else:
        print("Resp file is missing")
        return
		
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(1)
    print("[*] Listening on %s:%d" % (args.host, args.port))

	# send the first server response (as happened in PCAP)
    key_switch = 0
    try:
        while True:
            conn, addr = s.accept()
            print("[*] Connected from", addr)
            try:
			    # wait for client POST (read headers + body according to Content-Length)
                print("[*] Waiting for client's POST (headers+body)...")
                header_buf = recv_until_double_crlf(conn, timeout=5.0)
                req_full = read_http_body_from_buf(header_buf, conn)
                ts = int(time.time())
                req_fn = f"client_post_{ts}.http"
                #with open(req_fn, "wb") as f: f.write(req_full)
                #print("[*] Saved client ->", req_fn)
				
                type = None
                print(str(header_buf))
                if "/get" in str(header_buf):
                    print("[*] Client queried /get site")
                    type = "get"
                elif "/re" in str(header_buf):
                    print("[*] Client queried /re site")
                    type = "re"

                req_str = req_full.decode('latin1', errors='replace')
                print(req_str)
                client_status = None
                
                if "{\"d\":" in req_str:
                    print("Client sent data")
                    client_status = "s"
                else:
                    print("Client is waiting for a command")
                    client_status = "w"
					
                # Simple sequential handler; no threading to keep it tiny
                if client_status == "s":
                    print("[*] Sending response (resp1) len=", len(resp1))
                    conn.sendall(resp1)
                elif client_status == "w":
                    if key_switch >= 2:
                        print("[*] Sending response (resp4) len=", len(resp4))
                        conn.sendall(resp4)
                        break
                    elif key_switch == 1:
                        print("[*] Sending response (resp3) len=", len(resp3))
                        conn.sendall(resp3)
                        key_switch += 1
                    elif key_switch == 0:
                        print("[*] Sending response (resp2) len=", len(resp2))
                        conn.sendall(resp2)
                        key_switch += 1
            finally:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                conn.close()
    finally:
        s.close()
if __name__ == "__main__":
    main()

