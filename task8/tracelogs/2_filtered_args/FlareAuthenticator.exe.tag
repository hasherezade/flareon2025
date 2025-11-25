1b8a0;section: [.text]
1b8c2;ucrtbase.getenv
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8d8bc;CPUID:0
8d8de;CPUID:1
8d960;CPUID:7
8e3b0;ucrtbase._initterm_e
8e3f0;ucrtbase._set_app_type
8e400;ucrtbase._set_fmode
8e2e0;ucrtbase.__p__commode
8e350;ucrtbase._crt_atexit
8e340;ucrtbase._configure_narrow_argv
8d5ab;ntdll.RtlInitializeSListHead
8e330;ucrtbase._configthreadlocale
8e380;ucrtbase._initialize_narrow_environment
8d0d6;ucrtbase.[_initterm_e+23]*
8d0f3;ucrtbase.[_initterm_e+23]*
8e3a0;ucrtbase._initterm
8d673;kernel32.SetUnhandledExceptionFilter
8e410;ucrtbase._set_new_mode
8e370;ucrtbase._get_initial_narrow_environment
8e2d0;ucrtbase.__p___argv
8e2c0;ucrtbase.__p___argc
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a2621bb70 -> {\x10S&&Z\x02\x00\x00}
	Arg[1] = 0
	Arg[2] = 0

memmove returned:
	ptr 0x0000025a2621bb70 -> {\x10S&&Z\x02\x00\x00}

8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a2626bbe0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a2621bb70 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000008 = 8

memmove changed:
	Arg[0] = ptr 0x0000025a2626bbe0 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a2626bbe0 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a2626c220 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a2626bbe0 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000010 = 16

memmove changed:
	Arg[0] = ptr 0x0000025a2626c220 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a2626c220 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a262cc080 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a2626c220 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000018 = 24

memmove changed:
	Arg[0] = ptr 0x0000025a262cc080 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a262cc080 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a262c6d00 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a262cc080 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000020 = 32

memmove changed:
	Arg[0] = ptr 0x0000025a262c6d00 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a262c6d00 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a262caf60 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a262c6d00 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000030 = 48

memmove changed:
	Arg[0] = ptr 0x0000025a262caf60 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a262caf60 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a262728f0 -> {\xff\xe5\x00W\x00H\xff\xf0}
	Arg[1] = ptr 0x0000025a262caf60 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000048 = 72

memmove changed:
	Arg[0] = ptr 0x0000025a262728f0 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a262728f0 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a2626dfa0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a262728f0 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000068 = 104

memmove changed:
	Arg[0] = ptr 0x0000025a2626dfa0 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a2626dfa0 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a262d14c0 -> {\x904*&Z\x02\x00\x00}
	Arg[1] = ptr 0x0000025a2626dfa0 -> {\x10S&&Z\x02\x00\x00}
	Arg[2] = 0x0000000000000098 = 152

memmove changed:
	Arg[0] = ptr 0x0000025a262d14c0 -> {\x10S&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a262d14c0 -> {\x10S&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e270;vcruntime140.memchr
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e270;vcruntime140.memchr
8e430;ucrtbase.malloc
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e2a0;vcruntime140.memset
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e1d0;kernel32.FreeConsole
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
8e440;ucrtbase.strcmp
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaa920 -> L"1"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8faf8 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaa920 -> L"1"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8faf8 -> L"1"

memmove returned:
	ptr 0x000000d804f8faf8 -> L"1"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaaa60 -> L"2"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8faf9 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaaa60 -> L"2"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8faf9 -> L"2"

memmove returned:
	ptr 0x000000d804f8faf9 -> L"2"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaa780 -> L"3"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fafa -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaa780 -> L"3"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fafa -> L"3"

memmove returned:
	ptr 0x000000d804f8fafa -> L"3"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaad20 -> L"4"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fafb -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaad20 -> L"4"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fafb -> L"4"

memmove returned:
	ptr 0x000000d804f8fafb -> L"4"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaabc0 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fafc -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaabc0 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fafc -> L"5"

memmove returned:
	ptr 0x000000d804f8fafc -> L"5"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae40 -> L"6"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fafd -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaae40 -> L"6"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fafd -> L"6"

memmove returned:
	ptr 0x000000d804f8fafd -> L"6"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae00 -> L"7"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fafe -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaae00 -> L"7"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fafe -> L"7"

memmove returned:
	ptr 0x000000d804f8fafe -> L"7"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaad80 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8faff -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaad80 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8faff -> L"8"

memmove returned:
	ptr 0x000000d804f8faff -> L"8"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae00 -> L"9"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb00 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaae00 -> L"9"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb00 -> L"9"

memmove returned:
	ptr 0x000000d804f8fb00 -> L"9"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae20 -> L"0"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb01 -> {\x00\x00\x00\x00\x00\x00\x00\x0a}
	Arg[1] = ptr 0x0000025a63aaae20 -> L"0"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb01 -> L"0"

memmove returned:
	ptr 0x000000d804f8fb01 -> L"0"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae40 -> L"1"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb02 -> {\x00\x00\x00\x00\x00\x00\x0b\x00}
	Arg[1] = ptr 0x0000025a63aaae40 -> L"1"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb02 -> L"1"

memmove returned:
	ptr 0x000000d804f8fb02 -> L"1"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae40 -> L"2"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb03 -> {\x00\x00\x00\x00\x00\x0c\x00\x00}
	Arg[1] = ptr 0x0000025a63aaae40 -> L"2"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb03 -> L"2"

memmove returned:
	ptr 0x000000d804f8fb03 -> L"2"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaae60 -> L"3"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb04 -> {\x00\x00\x00\x00\x0d\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaae60 -> L"3"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb04 -> L"3"

memmove returned:
	ptr 0x000000d804f8fb04 -> L"3"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaa6a0 -> L"4"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb05 -> {\x00\x00\x00\x0e\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaa6a0 -> L"4"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb05 -> {4\x00\x00\x0e\x00\x00\x00\x00}

memmove returned:
	ptr 0x000000d804f8fb05 -> {4\x00\x00\x0e\x00\x00\x00\x00}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaa6c0 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000d804f8fb06 -> {\x00\x00\x0f\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x0000025a63aaa6c0 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000d804f8fb06 -> {5\x00\x0f\x00\x00\x00\x00\x00}

memmove returned:
	ptr 0x000000d804f8fb06 -> {5\x00\x0f\x00\x00\x00\x00\x00}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaa6e0 -> L"6"

strlen returned:
	0x0000000000000001 = 1

8e430;ucrtbase.malloc
8e280;vcruntime140.memcpy
memmove:
	Arg[0] = ptr 0x0000025a63a13230 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000000d804f8faf8 -> "123456789012345"
	Arg[2] = 0x000000000000000f = 15

memmove changed:
	Arg[0] = ptr 0x0000025a63a13230 -> {12345678}

memmove returned:
	ptr 0x0000025a63a13230 -> {12345678}

8e280;vcruntime140.memcpy
memmove:
	Arg[0] = ptr 0x0000025a63a1323f -> {@\xdf\x16\x00\x00o\x00n}
	Arg[1] = ptr 0x0000025a63aaa6e0 -> L"6"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a1323f -> {6\xdf\x16\x00\x00o\x00n}

memmove returned:
	ptr 0x0000025a63a1323f -> {6\xdf\x16\x00\x00o\x00n}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaafa0 -> L"7"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13240 -> {\x00\x16\x00\x00o\x00n\x00}
	Arg[1] = ptr 0x0000025a63aaafa0 -> L"7"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13240 -> {7\x16\x00\x00o\x00n\x00}

memmove returned:
	ptr 0x0000025a63a13240 -> {7\x16\x00\x00o\x00n\x00}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aab280 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13241 -> {\x00\x00\x00o\x00n\x00\x00}
	Arg[1] = ptr 0x0000025a63aab280 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13241 -> {8\x00\x00o\x00n\x00\x00}

memmove returned:
	ptr 0x0000025a63a13241 -> {8\x00\x00o\x00n\x00\x00}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aab4a0 -> L"9"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13242 -> {\x00\x00o\x00n\x00\x00w}
	Arg[1] = ptr 0x0000025a63aab4a0 -> L"9"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13242 -> {9\x00o\x00n\x00\x00w}

memmove returned:
	ptr 0x0000025a63a13242 -> {9\x00o\x00n\x00\x00w}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aab2a0 -> L"0"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13243 -> {\x00o\x00n\x00\x00w&}
	Arg[1] = ptr 0x0000025a63aab2a0 -> L"0"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13243 -> "0o"

memmove returned:
	ptr 0x0000025a63a13243 -> "0o"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aab380 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13244 -> {\x00\x00n\x00\x00w&&}
	Arg[1] = ptr 0x0000025a63aab380 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13244 -> {8\x00n\x00\x00w&&}

memmove returned:
	ptr 0x0000025a63a13244 -> {8\x00n\x00\x00w&&}

1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaaf60 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13245 -> {\x00n\x00\x00w&&Z}
	Arg[1] = ptr 0x0000025a63aaaf60 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13245 -> "5n"

memmove returned:
	ptr 0x0000025a63a13245 -> "5n"

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaade0 -> L"2"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13246 -> {\x00\x00\x00w&&Z\x02}
	Arg[1] = ptr 0x0000025a63aaade0 -> L"2"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13246 -> {2\x00\x00w&&Z\x02}

memmove returned:
	ptr 0x0000025a63a13246 -> {2\x00\x00w&&Z\x02}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaaba0 -> L"1"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13247 -> {\x00\x00w&&Z\x02\x00}
	Arg[1] = ptr 0x0000025a63aaaba0 -> L"1"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13247 -> {1\x00w&&Z\x02\x00}

memmove returned:
	ptr 0x0000025a63a13247 -> {1\x00w&&Z\x02\x00}

8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x0000025a63aaa6e0 -> L"4"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x0000025a63a13248 -> {\x00w&&Z\x02\x00\x00}
	Arg[1] = ptr 0x0000025a63aaa6e0 -> L"4"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x0000025a63a13248 -> {4w&&Z\x02\x00\x00}

memmove returned:
	ptr 0x0000025a63a13248 -> {4w&&Z\x02\x00\x00}

8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
8e420;ucrtbase.free
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8d616;kernel32.GetModuleHandleW
8e2b0;ucrtbase.exit
8d8a3;ucrtbase.[_execute_onexit_table+156]*
