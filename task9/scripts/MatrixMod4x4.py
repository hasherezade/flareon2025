from math import gcd

# ---------- small helpers ----------
def modinv(a: int, mod: int) -> int:
    """Modular inverse using Python's built-in pow when possible."""
    # raises ValueError if not invertible
    return pow(a % mod, -1, mod)

def lcm(a: int, b: int) -> int:
    return a // gcd(a, b) * b

def lcm_many(nums):
    from functools import reduce
    return reduce(lcm, nums, 1)

def ceil_log_p_n(p: int, n: int) -> int:
    """smallest m with p**m >= n (p >= 2, n >= 1)."""
    m, pk = 0, 1
    while pk < n:
        pk *= p
        m += 1
    return m

# ---------- matrix ops over Z_mod ----------
def mat_size(A):
    n = len(A)
    assert all(len(row) == n for row in A), "matrix must be square"
    return n

def mat_id(n, mod):
    I = [[0]*n for _ in range(n)]
    for i in range(n):
        I[i][i] = 1 % mod
    return I

def mat_mod(A, mod):
    n = mat_size(A)
    return [[a % mod for a in row] for row in A]

def mat_mul_mod(A, B, mod):
    n = mat_size(A)
    assert mat_size(B) == n
    C = [[0]*n for _ in range(n)]
    for i in range(n):
        Ai = A[i]
        Ci = C[i]
        for k in range(n):
            aik = Ai[k] % mod
            if aik == 0:
                continue
            Bk = B[k]
            for j in range(n):
                Ci[j] = (Ci[j] + aik * (Bk[j] % mod)) % mod
    return C

def mat_pow_mod(M, e: int, mod: int):
    n = mat_size(M)
    base = mat_mod(M, mod)
    R = mat_id(n, mod)
    x = e
    while x > 0:
        if x & 1:
            R = mat_mul_mod(R, base, mod)
        x >>= 1
        if x:
            base = mat_mul_mod(base, base, mod)
    return R

def mat_inv_mod(A, mod: int):
    """
    Gauss–Jordan inversion over Z_mod.
    Returns inverse if exists (all pivots invertible modulo mod), else raises ValueError.
    """
    n = mat_size(A)
    A = mat_mod(A, mod)
    I = mat_id(n, mod)

    for col in range(n):
        pivot = None
        inv_pivot = None
        # find a row with invertible pivot in this column
        for r in range(col, n):
            a = A[r][col]
            if a % mod != 0:
                try:
                    inv = modinv(a, mod)
                    pivot, inv_pivot = r, inv
                    break
                except ValueError:
                    pass
        if pivot is None:
            raise ValueError("matrix not invertible modulo mod (pivot not coprime to mod)")

        if pivot != col:
            A[col], A[pivot] = A[pivot], A[col]
            I[col], I[pivot] = I[pivot], I[col]

        # normalize pivot row
        for j in range(n):
            A[col][j] = (A[col][j] * inv_pivot) % mod
            I[col][j] = (I[col][j] * inv_pivot) % mod

        # eliminate other rows
        for r in range(n):
            if r == col:
                continue
            factor = A[r][col]
            if factor:
                for j in range(n):
                    A[r][j] = (A[r][j] - factor * A[col][j]) % mod
                    I[r][j] = (I[r][j] - factor * I[col][j]) % mod

    return I

# ---------- step back one multiply ----------
def step_back_previous_result(R_next, M, mod):
    """Given R_next = R_prev * M (mod), recover R_prev."""
    Minv = mat_inv_mod(M, mod)
    return mat_mul_mod(R_next, Minv, mod)

# ---------- e-th root over F_p (p must be prime) ----------
def matrix_eth_root_over_fp(R, e: int, p: int, use_full_gl_exponent=False):
    """
    Recover an e-th root M such that R = M^e (mod p), if possible,
    """
    n = mat_size(R)
    # lcm(p^k - 1, k = 1..n)
    terms = []
    pk = p
    for k in range(1, n+1):
        terms.append(pk - 1)
        pk *= p  # p^(k+1)
    Lam = lcm_many(terms)

    if use_full_gl_exponent:
        Lam *= pow(p, ceil_log_p_n(p, n))

    if gcd(e, Lam) != 1:
        raise ValueError("Exponent not invertible: cannot invert the map on this subgroup.")

    d = pow(e, -1, Lam)

    # Return R^d mod p
    return mat_pow_mod(R, d, p)

# ---------- pretty print ----------
def mat_to_hex(A):
    return ["[" + ", ".join(f"0x{v:016x}" for v in row) + "]," for row in A]


def inverse_exponentiation(R, e, P):
    return matrix_eth_root_over_fp(R, e, P, use_full_gl_exponent=False)
    
