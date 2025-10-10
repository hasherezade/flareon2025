#pragma once
#include <windows.h>

extern BYTE* g_Buffer1;

BYTE* f_type1(BYTE* arg1, size_t dll_id, const uint64_t kQargs[4])
{
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;
    arg1_d[0] ^= verif[dll_id];

    char flag = *arg1 & 1;
    *arg1 |= 1;

    uint64_t qwords[5] = { 0 };
    qwords[0] = kQargs[0];
    qwords[1] = kQargs[1];
    *(int64_t*)((char*)&qwords[1] + 7) = kQargs[2];
    *(int64_t*)((char*)&qwords[2] + 7) = kQargs[3];

    BYTE _chunk_copy[64] = { 0 };

    uint64_t backup1[4] = { 0 };
    backup1[0] = 1;

    for (size_t i = 0; i <= 31; ++i)
        _chunk_copy[i + 32] = *((BYTE*)arg1_d + i);

    for (size_t j = 0; j <= 30; ++j)
    {
        for (size_t k = 0; k <= 7; ++k)
        {
            if (((int)*((BYTE*)qwords + j) >> k) & 1)
            {
                int v18 = 0;
                for (size_t m = 0; m <= 31; ++m)
                {
                    for (size_t n = 0; n <= m; ++n)
                        v18 += *((BYTE*)backup1 + n) * _chunk_copy[m - n + 32];
                    _chunk_copy[m] = v18;
                    v18 >>= 8;
                }
                for (size_t ii = 0; ii <= 31; ++ii)
                    *((BYTE*)backup1 + ii) = _chunk_copy[ii];
            }
            int v14 = 0;
            for (size_t jj = 0; jj <= 31; ++jj)
            {
                for (size_t kk = 0; kk <= jj; ++kk)
                    v14 += _chunk_copy[kk + 32] * _chunk_copy[jj - kk + 32];
                _chunk_copy[jj] = v14;
                v14 >>= 8;
            }
            for (size_t mm = 0; mm <= 31; ++mm)
                _chunk_copy[mm + 32] = _chunk_copy[mm];
        }
    }
    for (size_t pos1 = 0; pos1 <= 31; ++pos1)
        *((BYTE*)arg1 + pos1) = *((BYTE*)backup1 + pos1);
    *(BYTE*)arg1 ^= flag ^ 1;
    return arg1;
}

BYTE* f_type2(BYTE* arg1, size_t dll_id, const uint64_t kQargs[33])
{
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;
    arg1_d[0] ^= verif[dll_id];

    for (size_t i = 0; i <= 31; ++i)
    {
        arg1[i] = *((BYTE*)kQargs + arg1[i]);
    }
    return arg1;
}


BYTE* f_type3(BYTE* arg1, size_t dll_id, const uint64_t kQargs[4])
{
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;
    arg1_d[0] ^= verif[dll_id];

    BYTE backup1[32] = { 0 };

    for (size_t i = 0; i <= 31; ++i)
    {
        backup1[i] = arg1[*((BYTE*)kQargs + i)];
    }
    for (size_t j = 0; j <= 31; ++j)
    {
        arg1[j] = backup1[j];
    }
    return arg1;
}
