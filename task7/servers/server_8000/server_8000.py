#!/usr/bin/env python3

import argparse, socket, time, os

DEFAULT_RESP1 = b"""HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.11
Date: Wed, 20 Aug 2025 06:12:07 GMT
Content-type: application/json

{\"d\": \"085d8ea282da6cf76bb2765bc3b26549a1f6bdf08d8da2a62e05ad96ea645c685da48d66ed505e2e28b968d15dabed15ab1500901eb9da4606468650f72550483f1e8c58ca13136bb8028f976bedd36757f705ea5f74ace7bd8af941746b961c45bcac1eaf589773cecf6f1c620e0e37ac1dfc9611aa8ae6e6714bb79a186f47896f18203eddce97f496b71a630779b136d7bf0c82d560\"}"""

DEFAULT_RESP2 = b"""HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.11
Date: Wed, 20 Aug 2025 06:12:07 GMT
Content-type: application/json

{\"d\": \"5134c8a46686f2950972712f2cd84174\"}"""

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
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--resp1", help="path to file with full HTTP response bytes for the response")
    args = ap.parse_args()

    if args.resp1 and os.path.exists(args.resp1):
        resp1 = open(args.resp1,"rb").read()
        print("Using RESP1 from file")
    else:
        resp1 = DEFAULT_RESP1
        print("Using default RESP1")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(1)
    print("[*] Listening on %s:%d" % (args.host, args.port))
    conn,addr = s.accept()
    print("[*] Connected from", addr)

    # wait for client POST (read headers + body according to Content-Length)
    print("[*] Waiting for client's POST (headers+body)...")
    header_buf = recv_until_double_crlf(conn, timeout=5.0)
    req_full = read_http_body_from_buf(header_buf, conn)
    ts = int(time.time())
    req_fn = f"client_post_{ts}.http"
    with open(req_fn, "wb") as f: f.write(req_full)
    print("[*] Saved client POST ->", req_fn)
    print(req_full.decode('latin1', errors='replace'))
	
	# send the first server response (as happened in PCAP)
    print("[*] Sending first response (resp1) len=", len(resp1))
    conn.sendall(resp1)

    print("[*] Done. Closing connection.")
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except: pass
    conn.close()
    s.close()

if __name__ == "__main__":
    main()

