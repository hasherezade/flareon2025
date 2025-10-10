#pragma once
#include <windows.h>

extern BYTE* g_Buffer1;

// utils:
static void mul256(const BYTE* a, const BYTE* b, BYTE* out) {
    uint16_t carry;
    uint32_t acc;
    BYTE tmp[32] = { 0 };
    for (size_t i = 0; i < 32; ++i) {
        carry = 0;
        for (size_t j = 0; j + i < 32; ++j) {
            acc = tmp[i + j] + a[j] * (uint32_t)b[i] + carry;
            tmp[i + j] = (BYTE)acc;
            carry = (uint16_t)(acc >> 8);
        }
        // high overflow beyond 32 bytes is discarded modulo 2^256
    }
    memcpy(out, tmp, 32);
}

static void square256(const BYTE* a, BYTE* out) {
    mul256(a, a, out);
}

// Modular exponentiation y = base^exp (exp given as little-endian bytes, exp_bits valid)
static void pow_mod2_256(const BYTE* base_in, const BYTE* exp_le, size_t exp_bits, BYTE* out) {
    BYTE base[32], res[32];
    memcpy(base, base_in, 32);
    // res = 1
    memset(res, 0, 32);
    res[0] = 1;

    for (size_t bit = 0; bit < exp_bits; ++bit) {
        if ((exp_le[bit >> 3] >> (bit & 7)) & 1) {
            BYTE tmp[32];
            mul256(res, base, tmp);
            memcpy(res, tmp, 32);
        }
        // base = base^2
        BYTE tmp2[32];
        square256(base, tmp2);
        memcpy(base, tmp2, 32);
    }
    memcpy(out, res, 32);
}

// Compute d = E^{-1} mod 2^255 (E must be odd). Newton/Hensel lifting.
// We work mod 2^k, doubling k each round, using 256-bit ops and masking.
static void inv_mod_2_255(const BYTE* E, BYTE* d) {
    // x0 = 1 (inverse mod 2)
    memset(d, 0, 32);
    d[0] = 1;

    BYTE t[32], two_minus_Ex[32], newx[32];
    // We’ll iterate precisions k = 2,4,8,...,256; final mask to 255 bits.
    for (int k = 1; k <= 8; ++k) { // 8 doublings: 2 -> 4 -> ... -> 256
        // t = E * d  (mod 2^256)
        mul256(E, d, t);
        // two_minus_Ex = 2 - t  (mod 2^256)
        memset(two_minus_Ex, 0, 32);
        two_minus_Ex[0] = 2;
        // two_minus_Ex = two_minus_Ex - t
        uint16_t borrow = 0;
        for (int i = 0; i < 32; ++i) {
            int v = (int)two_minus_Ex[i] - (int)t[i] - borrow;
            two_minus_Ex[i] = (BYTE)(v & 0xFF);
            borrow = (v < 0);
        }
        // newx = d * (2 - E*d)
        mul256(d, two_minus_Ex, newx);

        // Mask to current precision: cur_bits = 1<<(k)  (k rounds: bits = 2,4,...,256)
        size_t cur_bits = (size_t)1 << k;
        size_t full = cur_bits >> 3;
        BYTE mask = (cur_bits & 7) ? (BYTE)((1u << (cur_bits & 7)) - 1u) : 0xFF;
        memcpy(d, newx, 32);
        if (full < 32) {
            if ((cur_bits & 7) != 0) {
                d[full] &= mask;
                ++full;
            }
            for (size_t i = full; i < 32; ++i) d[i] = 0;
        }
    }
    // Reduce to 255 bits: clear the top bit of byte 31.
    d[31] &= 0x7F;
}

// Rebuild the 31-byte exponent bytes exactly like the forward code does.
static void build_E_bytes(const uint64_t kQargs[4], BYTE Ebytes[31]) {
    uint64_t qwords[5] = { 0 };
    qwords[0] = kQargs[0];
    qwords[1] = kQargs[1];
    *(int64_t*)((char*)&qwords[1] + 7) = (int64_t)kQargs[2];
    *(int64_t*)((char*)&qwords[2] + 7) = (int64_t)kQargs[3];
    memcpy(Ebytes, (const BYTE*)qwords, 31); // take first 31 bytes
}

// --- The inverse of f_type1 ---

BYTE* f_type1_inv(BYTE* arg1, size_t dll_id, const uint64_t kQargs[4]) {
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;

    // 1) Recover flag from final parity and undo the last XOR on byte 0
    BYTE flag = (BYTE)(arg1[0] & 1);          // since y is odd iff flag==1
    arg1[0] ^= (BYTE)(flag ^ 1);              // now arg1 holds y1 (odd)

    // 2) Build exponent E (31 bytes LE) and compute d = E^{-1} mod 2^255
    BYTE Ebytes[31];
    build_E_bytes(kQargs, Ebytes);

    // Sanity: E must be odd
    if ((Ebytes[0] & 1u) == 0) {
        // Not invertible; caller’s data would be ambiguous. (You may handle differently.)
        return NULL;
    }

    BYTE E256[32] = { 0 };          // put E in 32 bytes (LE)
    memcpy(E256, Ebytes, 31);

    BYTE d[32];
    inv_mod_2_255(E256, d);       // d = E^{-1} mod 2^255 (as 32 bytes, top bit clear)

    // 3) x1 = y1^d (mod 2^256)
    BYTE x1[32];
    pow_mod2_256(arg1, d, 255, x1); // only 255 bits of d are meaningful

    // 4) Restore original LSB (undo earlier |=1)
    x1[0] = (BYTE)((x1[0] & ~1u) | (flag & 1u));

    // 5) Undo the very first XOR on the first DWORD
    DWORD* x1_d = (DWORD*)x1;
    x1_d[0] ^= verif[dll_id];

    // 6) Write back
    memcpy(arg1, x1, 32);
    return arg1;
}

//---
// --- The inverse of f_type2 ---

BYTE* f_type2_inv(BYTE* arg1, size_t dll_id, const uint64_t kQargs[33])
{
    // Treat kQargs as a 256-byte S-box: T[i] = ((BYTE*)kQargs)[i]
    const BYTE* T = (const BYTE*)kQargs;

    // Build inverse S-box (assumes T is a permutation of 0..255)
    BYTE invT[256];
    for (int i = 0; i < 256; ++i) {
        invT[T[i]] = (BYTE)i;
    }

    // 1) Undo the byte substitution on all 32 bytes
    for (size_t i = 0; i < 32; ++i) {
        arg1[i] = invT[arg1[i]];
    }

    // 2) Undo the initial DWORD XOR (XOR is its own inverse)
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;   // must be the same verif[0] as used in f_type2
    arg1_d[0] ^= verif[dll_id];

    return arg1;
}

BYTE* f_type3_inv(BYTE* arg1, size_t dll_id, const uint64_t kQargs[4])
{
    const BYTE* p = (const BYTE*)kQargs; // 32-byte permutation
    BYTE tmp[32];

    // Undo the permutation:
    // fwd: out[i] = in[p[i]]
    // inv: in[idx] = out[j] where idx = p[j]  -> tmp[p[j]] = arg1[j]
    for (size_t j = 0; j < 32; ++j) {
        tmp[p[j]] = arg1[j];
    }
    for (size_t i = 0; i < 32; ++i) {
        arg1[i] = tmp[i];
    }

    // Undo the initial XOR (XOR is its own inverse)
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;
    arg1_d[0] ^= verif[dll_id];

    return arg1;
}
