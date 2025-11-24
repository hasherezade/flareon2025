void fetch_input()
{
  _QWORD *v0; // rax
  _QWORD *v1; // rax
  unsigned __int64 v2; // r8
  _QWORD *v3; // rax
  unsigned __int64 v4; // rax
  __int64 v5; // rdx
  unsigned __int64 v6; // [rsp+7D0h] [rbp+750h]
  _QWORD v7[24]; // [rsp+9B8h] [rbp+938h] BYREF
  _QWORD v8[36]; // [rsp+A78h] [rbp+9F8h] BYREF
  _QWORD v9[6]; // [rsp+B98h] [rbp+B18h] BYREF
  _QWORD v10[12]; // [rsp+BC8h] [rbp+B48h] BYREF
  _QWORD v11[6]; // [rsp+C28h] [rbp+BA8h] BYREF
  _QWORD v12[6]; // [rsp+C58h] [rbp+BD8h] BYREF
  _QWORD v13[6]; // [rsp+C88h] [rbp+C08h] BYREF
  _QWORD v14[6]; // [rsp+CB8h] [rbp+C38h] BYREF
  _BYTE v15[32]; // [rsp+CE8h] [rbp+C68h] BYREF
  _BYTE *v16; // [rsp+D08h] [rbp+C88h]
  _QWORD v17[6]; // [rsp+D18h] [rbp+C98h] BYREF
  _QWORD v18[6]; // [rsp+D48h] [rbp+CC8h] BYREF
  _QWORD v19[6]; // [rsp+D78h] [rbp+CF8h] BYREF
  _BYTE v20[48]; // [rsp+DA8h] [rbp+D28h] BYREF
  _BYTE v21[40]; // [rsp+DD8h] [rbp+D58h] BYREF
  _BYTE v22[40]; // [rsp+E40h] [rbp+DC0h] BYREF
  _BYTE v23[88]; // [rsp+E68h] [rbp+DE8h] BYREF
  _BYTE v24[24]; // [rsp+EC0h] [rbp+E40h] BYREF
  _BYTE v25[72]; // [rsp+ED8h] [rbp+E58h] BYREF
  _BYTE v26[24]; // [rsp+F20h] [rbp+EA0h] BYREF
  _BYTE v27[16]; // [rsp+F38h] [rbp+EB8h] BYREF
  _BYTE v28[40]; // [rsp+F50h] [rbp+ED0h] BYREF
  _BYTE v29[24]; // [rsp+F78h] [rbp+EF8h] BYREF
  _BYTE v30[48]; // [rsp+F90h] [rbp+F10h] BYREF
  _BYTE v31[48]; // [rsp+FC8h] [rbp+F48h] BYREF
  __int64 v32; // [rsp+1000h] [rbp+F80h]

  v32 = -2;
  v19[4] = v27;
  v19[0] = v30;
  v19[3] = v25;
  v19[1] = v25;
  v19[5] = v24;
  v18[4] = v28;
  v18[0] = v27;
  v18[3] = v20;
  v18[1] = v21;
  v18[5] = v20;
  v17[4] = v27;
  v17[0] = v23;
  v17[3] = v18;
  v17[1] = v29;
  v17[5] = v18;
  v16 = v30;
  v14[4] = v22;
  v14[0] = v19;
  v14[3] = v15;
  v14[1] = v29;
  v14[5] = v26;
  v13[4] = v21;
  v13[0] = v28;
  v12[4] = v29;
  v12[0] = v31;
  v11[4] = v19;
  v11[0] = v23;
  v11[3] = v30;
  v11[1] = v19;
  v11[5] = v19;
  v10[10] = v20;
  v10[6] = v14;
  v10[9] = v21;
  v10[4] = v15;
  v10[0] = v18;
  v10[3] = v24;
  v9[4] = v14;
  v9[0] = v12;
  v9[3] = v10;
  v9[1] = v31;
  v8[34] = v31;
  v8[30] = v30;
  v8[33] = v14;
  v8[31] = v28;
  v8[35] = v15;
  v8[28] = v13;
  v8[24] = v10;
  v8[27] = v27;
  v8[22] = v13;
  v8[18] = v13;
  v8[16] = v26;
  v8[12] = v20;
  v8[10] = v22;
  v8[6] = v20;
  v8[9] = v18;
  v8[7] = v11;
  v8[11] = v17;
  v8[4] = v12;
  v8[0] = v27;
  v7[22] = v9;
  v7[18] = v11;
  v7[21] = v29;
  v7[19] = v8;
  v7[23] = v17;
  v7[16] = v23;
  v7[12] = v29;
  v7[10] = v24;
  v7[4] = v18;
  v7[0] = v17;
  v7[3] = v15;
  v7[1] = v19;
  *(_QWORD *)(*(_QWORD *)((__int64 (*)(void))((char *)off_1400A68A0 - 0x50995BFFD33065E5LL))() + 16LL) = 7603;
  v0 = (_QWORD *)((__int64 (__fastcall *)(_QWORD *))((char *)off_1400C65A8 + 0x6C576166C2CB8CBDLL))(v7);
  *(_QWORD *)(*(_QWORD *)((__int64 (__fastcall *)(_QWORD))((char *)off_1400A6878 - 0xD906C5D983E86E2LL))(*v0) + 48LL) = 7603;
  v1 = (_QWORD *)((__int64 (__fastcall *)(_QWORD *))((char *)off_1400C2BC0 - 0x5263BADD33DA296CLL))(v7);
  v2 = 585153996LL
     * *(_QWORD *)(*(_QWORD *)((__int64 (__fastcall *)(_QWORD))((char *)off_1400C4D00 - 0x6673BBC6A8598DAALL))(*v1)
                 + 48LL)
     % 0x415699ECuLL;
  v6 = (((2 * (v2 - (v2 | 0xFFFFFFFFDE1F3307uLL)) - 1136761330) | ((v2 | 0xFFFFFFFFDE1F3307uLL) - (v2 & 0x5E1F3304)))
      + ((2 * (v2 - (v2 | 0xFFFFFFFFDE1F3307uLL)) - 1136761330) & ((v2 | 0xFFFFFFFFDE1F3307uLL) - (v2 & 0x5E1F3304))))
     % 0x415699EC;
  v3 = (_QWORD *)((__int64 (__fastcall *)(_QWORD *))((char *)off_1400B0768 - 0x4963DF634C191083LL))(v7);
  *(_QWORD *)(*(_QWORD *)((__int64 (__fastcall *)(_QWORD))((char *)off_1400C24A8 - 0xBD01726A630EF11LL))(*v3) + 48LL) = v6;
  v4 = *(_QWORD *)((char *)off_1400BEAD8 + 0x5DAA6882B5D30C41LL) | 0x97EE750CB1FF72BCuLL;
  v5 = 2 * (*(_QWORD *)((char *)off_1400BEAD8 + 0x5DAA6882B5D30C41LL) - v4) + 0x2FDCEA1963FEE578LL;
  __asm { jmp     rax }
}
