# Sequences - CTF Writeup

## Challenge Overview

- **Challenge Name:** Sequences
- **Category:** Cryptography / Programming
- **Difficulty:** Medium-Hard

### Description
The challenge presents a linear recurrence function that needs to be optimized to run fast enough to retrieve the flag. The hint indicates that even an efficient solution might take several seconds, but if it's taking several minutes, a different approach is needed.

---

## File Analysis

### sequences.py

The main challenge file contains:

1. **Configuration constants:**
   - `ITERS = 20,000,000` (2×10⁷) - The target iteration
   - `VERIF_KEY` - MD5 checksum for verification
   - `ENCRYPTED_FLAG` - XOR-encrypted flag

2. **Recursive function with memoization:**
   ```python
   @functools.cache
   def m_func(i):
       if i == 0: return 1
       if i == 1: return 2
       if i == 2: return 3
       if i == 3: return 4
       return 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)
   ```

3. **Flag decryption:**
   - Takes the solution modulo 10¹⁰⁰⁰⁰
   - Verifies MD5 hash against `VERIF_KEY`
   - Decrypts using SHA256-derived key with XOR

---

## The Mathematical Problem

### Recurrence Relation

We need to calculate `m(20,000,000)` where:

```
m(i) = 21·m(i-1) + 301·m(i-2) - 9549·m(i-3) + 55692·m(i-4)
```

### Base Cases
- `m(0) = 1`
- `m(1) = 2`
- `m(2) = 3`
- `m(3) = 4`

### Why This is Difficult

The value of `m(20,000,000)` is astronomically large - it has thousands of digits! Computing this directly using naive recursion is infeasible for multiple reasons.

---

## Why the Naive Approach Fails

### 1. Recursion Depth Limit

Python's default recursion limit is typically 1000. With 20,000,000 recursive calls:
```
RecursionError: maximum recursion depth exceeded
```

Even if we increase the limit with `sys.setrecursionlimit()`, we'd hit stack overflow issues.

### 2. Time Complexity

While `@functools.cache` provides memoization (avoiding redundant calculations), we still need to compute 20,000,000 values sequentially:
- **Time Complexity:** O(n) where n = 20,000,000
- **Space Complexity:** O(n) for storing all cached values

With numbers growing to thousands of digits, each arithmetic operation becomes increasingly expensive. This approach would take many minutes or even hours.

### 3. Memory Constraints

Storing 20 million large integers in memory would require gigabytes of RAM.

---

## The Solution: Matrix Exponentiation

### Key Insight

Linear recurrences can be represented as matrix multiplications. For our 4-term recurrence:

```
m(i)   = 21·m(i-1) + 301·m(i-2) - 9549·m(i-3) + 55692·m(i-4)
m(i-1) = 1·m(i-1) + 0·m(i-2) + 0·m(i-3) + 0·m(i-4)
m(i-2) = 0·m(i-1) + 1·m(i-2) + 0·m(i-3) + 0·m(i-4)
m(i-3) = 0·m(i-1) + 0·m(i-2) + 1·m(i-3) + 0·m(i-4)
```

### Transformation Matrix

```
┌           ┐   ┌            ┐   ┌            ┐
│ m(i)   │   │ 21  301 -9549 55692 │   │ m(i-1) │
│ m(i-1) │ = │ 1    0     0     0   │ × │ m(i-2) │
│ m(i-2) │   │ 0    1     0     0   │   │ m(i-3) │
│ m(i-3) │   │ 0    0     1     0   │   │ m(i-4) │
└           ┘   └            ┘   └            ┘
```

Let **M** be the transformation matrix:
```
    ┌                    ┐
    │ 21   301  -9549  55692 │
M = │  1     0      0      0   │
    │  0     1      0      0   │
    │  0     0      1      0   │
    └                    ┘
```

### Matrix Exponentiation

Instead of applying the transformation 20,000,000 times, we use **binary exponentiation**:

```
M^n can be computed in O(log n) matrix multiplications
```

For n = 20,000,000:
- Naive: 20,000,000 operations
- Binary exponentiation: ~log₂(20,000,000) ≈ 25 operations!

### Deriving m(n)

Once we compute M^(n-3), we can find m(n):

```
┌           ┐         ┌            ┐   ┌      ┐
│ m(n)   │         │            │   │ m(3)=4 │
│ m(n-1) │ = M^(n-3) │ × │ m(2)=3 │
│ m(n-2) │         │            │   │ m(1)=2 │
│ m(n-3) │         │            │   │ m(0)=1 │
└           ┘         └            ┘   └      ┘
```

So: `m(n) = M^(n-3)[0][0]×4 + M^(n-3)[0][1]×3 + M^(n-3)[0][2]×2 + M^(n-3)[0][3]×1`

### Modular Arithmetic

Since we only need `m(n) mod 10¹⁰⁰⁰⁰` (10,000 digits), we perform all operations modulo 10¹⁰⁰⁰⁰ to keep numbers manageable.

---

## Python Solution

```python
import hashlib
import sys

# Allow Python to handle large integer string conversions
sys.set_int_max_str_digits(10000)

ITERS = int(2e7)  # 20,000,000
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex(
    "42cbbce1487b443de1acf4834baed794f4bbd0dfe2d6046e248ff7962b"
)
MOD = 10**10000  # Keep last 10,000 digits


def mat_mul(A, B, mod):
    """Multiply two 4x4 matrices modulo mod"""
    C = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % mod
    return C


def mat_pow(A, p, mod):
    """Compute matrix power A^p using binary exponentiation"""
    # Initialize result as identity matrix
    res = [[0] * 4 for _ in range(4)]
    for i in range(4):
        res[i][i] = 1

    while p > 0:
        if p % 2 == 1:
            res = mat_mul(res, A, mod)
        A = mat_mul(A, A, mod)
        p //= 2

    return res


def solve():
    # Transformation matrix for the recurrence
    # m(i) = 21*m(i-1) + 301*m(i-2) - 9549*m(i-3) + 55692*m(i-4)
    M = [
        [21, 301, -9549, 55692],
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0]
    ]

    if ITERS < 4:
        # Base cases
        base = [1, 2, 3, 4]
        sol = base[ITERS]
    else:
        # Compute M^(ITERS-3)
        M_pow = mat_pow(M, ITERS - 3, MOD)

        # m(n) = first row of M^(n-3) dot product with [m(3), m(2), m(1), m(0)]
        # [m(3), m(2), m(1), m(0)] = [4, 3, 2, 1]
        sol = (
            M_pow[0][0] * 4 +
            M_pow[0][1] * 3 +
            M_pow[0][2] * 2 +
            M_pow[0][3] * 1
        ) % MOD

    sol_str = str(sol)
    sol_md5 = hashlib.md5(sol_str.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print(f"Incorrect solution: {sol_md5}")
        return

    # Decrypt flag using SHA256 of solution as key
    key = hashlib.sha256(sol_str.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()
    print(flag)


if __name__ == "__main__":
    solve()
```

---

## How the Flag is Decrypted

The flag decryption process in `decrypt_flag()` works as follows:

1. **Modulo Operation:**
   ```python
   sol = sol % (10**10000)
   ```
   This ensures we're only working with the last 10,000 digits of the enormous number.

2. **Verification:**
   ```python
   sol_md5 = hashlib.md5(sol.encode()).hexdigest()
   assert sol_md5 == VERIF_KEY
   ```
   The MD5 hash of the solution (as a string) must match the hardcoded verification key.

3. **Key Derivation:**
   ```python
   key = hashlib.sha256(sol.encode()).digest()
   ```
   The SHA256 hash of the solution string becomes the decryption key.

4. **XOR Decryption:**
   ```python
   flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()
   ```
   Each byte of the encrypted flag is XORed with the corresponding byte of the SHA256 key.

---

## Running the Solution

```bash
$ python3 solve.py
picoCTF{b1g_numb3rs_689693c6}
```

**Expected runtime:** 2-5 seconds (depending on hardware)

---

## Key Takeaways

1. **Matrix Exponentiation** reduces time complexity from O(n) to O(log n) for linear recurrences
2. **Binary exponentiation** is a fundamental algorithm for competitive programming and CTFs
3. **Modular arithmetic** keeps numbers manageable when dealing with massive values
4. Always look for mathematical optimizations when dealing with large iteration counts

---

## Final Flag

```
picoCTF{b1g_numb3rs_689693c6}
```
