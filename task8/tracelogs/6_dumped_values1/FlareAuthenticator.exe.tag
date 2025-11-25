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
	Arg[0] = ptr 0x000001f64674a740 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[1] = 0
	Arg[2] = 0

memmove returned:
	ptr 0x000001f64674a740 -> {\x10hyF\xf6\x01\x00\x00}

8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6468020c0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f64674a740 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000008 = 8

memmove changed:
	Arg[0] = ptr 0x000001f6468020c0 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f6468020c0 -> {\x10hyF\xf6\x01\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f646801de0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6468020c0 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000010 = 16

memmove changed:
	Arg[0] = ptr 0x000001f646801de0 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f646801de0 -> {\x10hyF\xf6\x01\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f646803c70 -> {*\x00;\x00\xf7\xff\xff\xff}
	Arg[1] = ptr 0x000001f646801de0 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000018 = 24

memmove changed:
	Arg[0] = ptr 0x000001f646803c70 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f646803c70 -> {\x10hyF\xf6\x01\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f646800660 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f646803c70 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000020 = 32

memmove changed:
	Arg[0] = ptr 0x000001f646800660 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f646800660 -> {\x10hyF\xf6\x01\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f646806f70 -> {\x00(\x00i\x00)\x00 }
	Arg[1] = ptr 0x000001f646800660 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000030 = 48

memmove changed:
	Arg[0] = ptr 0x000001f646806f70 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f646806f70 -> {\x10hyF\xf6\x01\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6467aca50 -> {\x00Y\x00o\xff\xf4\x00Y}
	Arg[1] = ptr 0x000001f646806f70 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000048 = 72

memmove changed:
	Arg[0] = ptr 0x000001f6467aca50 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f6467aca50 -> {\x10hyF\xf6\x01\x00\x00}

8e420;ucrtbase.free
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e430;ucrtbase.malloc
8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f64678e120 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6467aca50 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000068 = 104

memmove changed:
	Arg[0] = ptr 0x000001f64678e120 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f64678e120 -> {\x10hyF\xf6\x01\x00\x00}

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
	Arg[0] = ptr 0x000001f646806330 -> {`\x98{F\xf6\x01\x00\x00}
	Arg[1] = ptr 0x000001f64678e120 -> {\x10hyF\xf6\x01\x00\x00}
	Arg[2] = 0x0000000000000098 = 152

memmove changed:
	Arg[0] = ptr 0x000001f646806330 -> {\x10hyF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f646806330 -> {\x10hyF\xf6\x01\x00\x00}

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
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6bc0 -> L"1"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f778 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6bc0 -> L"1"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f778 -> L"1"

memmove returned:
	ptr 0x000000a66711f778 -> L"1"

				{ [rsp] -> 0xa667119fe8; rdi = 0xa66711a3e0; rsi = 0xa66711a3a0; rbp = 0xa6671194d0; rsp = 0xa667119450; rbx = 0xa667119fe8; rdx = 0x2000440400001; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; r12 = 0xa66711a0a8; r13 = 0xa667119ef8; r14 = 0xa667119ec8; r15 = 0xa66711a3c8; flags = 0x217 [ C=1 P=1 A=1 I=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x279342f; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ee0 -> L"2"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f779 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ee0 -> L"2"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f779 -> L"2"

memmove returned:
	ptr 0x000000a66711f779 -> L"2"

				{ rdx = 0x2000440400002; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xc678db8; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ee0 -> L"3"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f77a -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ee0 -> L"3"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f77a -> L"3"

memmove returned:
	ptr 0x000000a66711f77a -> L"3"

				{ rdx = 0x2000440400003; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x87d0f40; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ea0 -> L"4"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f77b -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ea0 -> L"4"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f77b -> L"4"

memmove returned:
	ptr 0x000000a66711f77b -> L"4"

				{ rdx = 0x2000440400004; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xcc48d40; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6a20 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f77c -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6a20 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f77c -> L"5"

memmove returned:
	ptr 0x000000a66711f77c -> L"5"

				{ rdx = 0x2000440400005; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xc60a7f3; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6a20 -> L"6"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f77d -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6a20 -> L"6"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f77d -> L"6"

memmove returned:
	ptr 0x000000a66711f77d -> L"6"

				{ rdx = 0x2000440400006; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x716c0d7; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ec0 -> L"6"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f77e -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ec0 -> L"6"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f77e -> L"6"

memmove returned:
	ptr 0x000000a66711f77e -> L"6"

				{ rdx = 0x2000440400007; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x32c5f65; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6a60 -> L"7"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f77f -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6a60 -> L"7"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f77f -> L"7"

memmove returned:
	ptr 0x000000a66711f77f -> L"7"

				{ rdx = 0x2000440400008; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xb49d7af; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d67e0 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f780 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d67e0 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f780 -> L"8"

memmove returned:
	ptr 0x000000a66711f780 -> L"8"

				{ rdx = 0x2000440400009; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x1b186d3; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d68e0 -> L"9"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f781 -> {\x00\x00\x00\x00\x00\x00\x00\x0a}
	Arg[1] = ptr 0x000001f6048d68e0 -> L"9"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f781 -> L"9"

memmove returned:
	ptr 0x000000a66711f781 -> L"9"

				{ rdx = 0x200044040000a; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x545d8d5; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6dc0 -> L"0"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f782 -> {\x00\x00\x00\x00\x00\x00\x0b\x00}
	Arg[1] = ptr 0x000001f6048d6dc0 -> L"0"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f782 -> L"0"

memmove returned:
	ptr 0x000000a66711f782 -> L"0"

				{ rdx = 0x200044040000b; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x6b2f406; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d68e0 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f783 -> {\x00\x00\x00\x00\x00\x0c\x00\x00}
	Arg[1] = ptr 0x000001f6048d68e0 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f783 -> L"8"

memmove returned:
	ptr 0x000000a66711f783 -> L"8"

				{ rdx = 0x200044040000c; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x9a868c; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ee0 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f784 -> {\x00\x00\x00\x00\x0d\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ee0 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f784 -> L"5"

memmove returned:
	ptr 0x000000a66711f784 -> L"5"

				{ rdx = 0x200044040000d; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x7024229; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ba0 -> L"2"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f785 -> {\x00\x00\x00\x0e\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ba0 -> L"2"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f785 -> {2\x00\x00\x0e\x00\x00\x00\x00}

memmove returned:
	ptr 0x000000a66711f785 -> {2\x00\x00\x0e\x00\x00\x00\x00}

				{ rdx = 0x200044040000e; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x48bdaae; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ce0 -> L"1"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000000a66711f786 -> {\x00\x00\x0f\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000001f6048d6ce0 -> L"1"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000000a66711f786 -> {1\x00\x0f\x00\x00\x00\x00\x00}

memmove returned:
	ptr 0x000000a66711f786 -> {1\x00\x0f\x00\x00\x00\x00\x00}

				{ rdx = 0x200044040000f; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x5f8f14f; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6960 -> L"1"

strlen returned:
	0x0000000000000001 = 1

8e430;ucrtbase.malloc
8e280;vcruntime140.memcpy
memmove:
	Arg[0] = ptr 0x000001f6048dcf70 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x000000a66711f778 -> "123456678908521"
	Arg[2] = 0x000000000000000f = 15

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf70 -> "123456678908521@-%"

memmove returned:
	ptr 0x000001f6048dcf70 -> "123456678908521@-%"

8e280;vcruntime140.memcpy
memmove:
	Arg[0] = ptr 0x000001f6048dcf7f -> "@-%"
	Arg[1] = ptr 0x000001f6048d6960 -> L"1"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf7f -> "1-%"

memmove returned:
	ptr 0x000001f6048dcf7f -> "1-%"

				{ rdx = 0x2000440400010; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x9d5d059; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6d00 -> L"2"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf80 -> {\x00%\x00\x00\xf6\x01\x00\x00}
	Arg[1] = ptr 0x000001f6048d6d00 -> L"2"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf80 -> "2%"

memmove returned:
	ptr 0x000001f6048dcf80 -> "2%"

				{ rdx = 0x2000440400011; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xdc0222f; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6b60 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf81 -> {\x00\x00\x00\xf6\x01\x00\x00\xe0}
	Arg[1] = ptr 0x000001f6048d6b60 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf81 -> {5\x00\x00\xf6\x01\x00\x00\xe0}

memmove returned:
	ptr 0x000001f6048dcf81 -> {5\x00\x00\xf6\x01\x00\x00\xe0}

				{ rdx = 0x2000440400012; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x3d1d2b6; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6d00 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf82 -> {\x00\x00\xf6\x01\x00\x00\xe0H}
	Arg[1] = ptr 0x000001f6048d6d00 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf82 -> {8\x00\xf6\x01\x00\x00\xe0H}

memmove returned:
	ptr 0x000001f6048dcf82 -> {8\x00\xf6\x01\x00\x00\xe0H}

				{ rdx = 0x2000440400013; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xd63209a; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6940 -> L"9"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf83 -> {\x00\xf6\x01\x00\x00\xe0Hz}
	Arg[1] = ptr 0x000001f6048d6940 -> L"9"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf83 -> {9\xf6\x01\x00\x00\xe0Hz}

memmove returned:
	ptr 0x000001f6048dcf83 -> {9\xf6\x01\x00\x00\xe0Hz}

				{ rdx = 0x2000440400014; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xb3c02cb; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6b20 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf84 -> {\x00\x01\x00\x00\xe0HzF}
	Arg[1] = ptr 0x000001f6048d6b20 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf84 -> {8\x01\x00\x00\xe0HzF}

memmove returned:
	ptr 0x000001f6048dcf84 -> {8\x01\x00\x00\xe0HzF}

				{ rdx = 0x2000440400015; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x6fb781e; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ec0 -> L"7"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf85 -> {\x00\x00\x00\xe0HzF\xf6}
	Arg[1] = ptr 0x000001f6048d6ec0 -> L"7"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf85 -> {7\x00\x00\xe0HzF\xf6}

memmove returned:
	ptr 0x000001f6048dcf85 -> {7\x00\x00\xe0HzF\xf6}

				{ rdx = 0x2000440400016; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xf2d7eee; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6ec0 -> L"4"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf86 -> {\x00\x00\xe0HzF\xf6\x01}
	Arg[1] = ptr 0x000001f6048d6ec0 -> L"4"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf86 -> {4\x00\xe0HzF\xf6\x01}

memmove returned:
	ptr 0x000001f6048dcf86 -> {4\x00\xe0HzF\xf6\x01}

				{ rdx = 0x2000440400017; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xca922ea; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6860 -> L"5"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf87 -> {\x00\xe0HzF\xf6\x01\x00}
	Arg[1] = ptr 0x000001f6048d6860 -> L"5"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf87 -> {5\xe0HzF\xf6\x01\x00}

memmove returned:
	ptr 0x000001f6048dcf87 -> {5\xe0HzF\xf6\x01\x00}

				{ rdx = 0x2000440400018; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0xadf00df; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
8e450;ucrtbase.strlen
strlen:
	Arg[0] = ptr 0x000001f6048d6980 -> L"8"

strlen returned:
	0x0000000000000001 = 1

8e290;vcruntime140.memmove
memmove:
	Arg[0] = ptr 0x000001f6048dcf88 -> {\x00HzF\xf6\x01\x00\x00}
	Arg[1] = ptr 0x000001f6048d6980 -> L"8"
	Arg[2] = 0x0000000000000001 = 1

memmove changed:
	Arg[0] = ptr 0x000001f6048dcf88 -> {8HzF\xf6\x01\x00\x00}

memmove returned:
	ptr 0x000001f6048dcf88 -> {8HzF\xf6\x01\x00\x00}

				{ rdx = 0x2000440400019; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; flags = 0x217 [ C=1 P=1 A=1 ]; }
15e99;[0] call rax # disasm start: get_translated1
				{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x4775803; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }
15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1
1b8fc;ntdll.[RtlActivateActivationContextUnsafeFast+11d]*
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
8d616;kernel32.GetModuleHandleW
8e2b0;ucrtbase.exit
8d8a3;ucrtbase.[_execute_onexit_table+156]*
