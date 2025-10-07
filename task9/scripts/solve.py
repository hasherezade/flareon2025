from MatrixMod4x4 import *

if __name__ == "__main__":
	P = 0xcfa801af34882c6d
	e = 0x0aaf4d006d2bd73f
	R = [
		[0x3583e6e5dc29bca2, 0x522445f36946c125, 0x4599fe2c44b4f3a8, 0x5868177cdb7b2749],
		[0xcb8f10fb525051f9, 0xbf1d0ce59e2b14dc, 0x34611ba4c7dff158, 0x7a9e7acfc93fe1c7],
		[0xa32c0a35c2f9bea2, 0x2de4d1a4b02967ad, 0xbf6179618d200abb, 0x1efc5ea6fd9d4436],
		[0xa64b4623235c1d64, 0x66c09d29f7862885, 0xbad1341f65b5d3c6, 0x58fc3a129737247c],
	]
	M_root = inverse_exponentiation(R, e, P)
	print("\n".join(mat_to_hex(M_root)))

    
