# Noisy Lucky Number - solve writeup

## Challenge summary

This challenge leaks structure in the ECDSA nonce generator. Most signatures are created with a nonce whose low 16 bits are fixed to the device `HW_ID`, while a few noisy signatures are generated from full entropy instead. That gives a hidden-number style bias: enough signatures share the same low 16-bit suffix to recover the secp256k1 private key with a differential equation setup and a lattice attack, even in the presence of outliers.

Recovered values:

- private key `d = 0xcfe6e61a5b40bb1648b0ce82722f508331702fcf2689560664f93e9cf292a8d2`
- `HW_ID = 0x0c2e`
- final flag `PUCTF26{y0u_4r3_1uck7_4nd_9O0d_47_5ub54mp1ing_d4102652fb095f2fDC40D346B7E02440}`

## Files provided

The challenge logic is in `chal.py`, and the captured signatures are in `task_data.json`.

- `chal.py`: generates 50 ECDSA signatures and encrypts the flag
- `task_data.json`: exported public key, curve order, encrypted flag, and 50 `(r, s, hash)` tuples

Local solver helpers in this folder that reproduce the attack:

- `solve.py`: main working solver used to recover the key and flag
- `bitlogik_attack.py`: alternate lattice attack implementation
- `backup_analyze.py`: exploratory/backup analysis script

## Vulnerability analysis of the nonce generator

The bug is in `EntropyMixer.generate_nonce()` in `chal.py`:

```python
raw_entropy = os.urandom(30)
mixed_buffer = struct.pack(">30sH", raw_entropy, self.hw_id)
return int.from_bytes(mixed_buffer, "big")
```

When `mixer_stable` is true, the nonce is a 32-byte value made from:

- 30 random bytes
- followed by the 16-bit `HW_ID`

So for stable signatures,

```text
k_i = 2^16 * q_i + c
```

where:

- `q_i` is unknown high-240-bit randomness
- `c = HW_ID` is the same fixed low-16-bit suffix every time

But `mixer_stable` is randomly false with probability about `36/256`, and then the code falls back to fully random 32-byte entropy:

```python
return int.from_bytes(os.urandom(32), "big")
```

That creates noisy outliers. After recovering the key and recomputing all nonces, the observed distribution is:

- 43 signatures with low 16 bits equal to `0x0c2e`
- 7 outliers with unrelated low 16 bits

This is exactly the kind of biased nonce leakage that breaks ECDSA.

## ECDSA equations

For each signature on hash `h_i`:

```text
s_i = k_i^(-1) (h_i + r_i d) mod n
```

Equivalently,

```text
k_i = s_i^(-1) (h_i + r_i d) mod n
```

Define:

```text
t_i = r_i * s_i^(-1) mod n
u_i = h_i * s_i^(-1) mod n
```

Then:

```text
k_i = t_i d + u_i mod n
```

For stable signatures, `k_i = 2^16 q_i + c`, so:

```text
t_i d + u_i - c = 2^16 q_i mod n
```

The unknown constant suffix `c` is shared across all good signatures.

## Why the fixed 16-bit suffix is exploitable

At first glance, knowing only 16 bits of each nonce may sound too small. The key observation is that the same 16 low bits are reused across many signatures. If we subtract one signature equation from another, the unknown suffix `c` cancels:

```text
(t_i - t_j) d + (u_i - u_j) = 2^16 (q_i - q_j) mod n
```

So every pair of stable signatures gives a relation whose right-hand side is an exact multiple of `2^16`. That is a Hidden Number Problem instance with known low bits after differencing.

The outliers do not satisfy this relation, but there are only 7 of them. With 43 good signatures out of 50, random subset sampling is enough to isolate subsets dominated by valid equations.

## Attack strategy

The working approach in `solve.py` is:

1. Parse each signature and compute `t_i = r_i/s_i mod n` and `u_i = h_i/s_i mod n`.
2. Choose a reference signature `j` and build differential relations
   `t = (t_i - t_j) mod n`, `u = (u_i - u_j) mod n`.
3. For random subsets of these relations, build a lattice encoding
   `t d + u = 2^16 * z mod n`.
4. Run `LLL`, then stronger `BKZ` passes (`15`, `25`) to search for the short vector containing `d`.
5. Test candidate private keys against the published compressed public key.
6. Once `d` is found, recompute all nonces from the signatures and count low-16 values to recover the repeated suffix `HW_ID`.
7. Decrypt the flag with `SHA256(d)` as the XOR keystream source.

This is essentially a differential HNP lattice attack with subset sampling to survive noisy signatures.

### Why subset sampling works

If we feed outliers directly into the lattice, the nice multiple-of-`2^16` structure is broken. Instead, `solve.py` repeatedly samples small subsets (`22` equations) and cycles over possible reference signatures. Since 43/50 signatures are good, many sampled subsets contain mostly or entirely valid equations, and one of those runs produces the correct short vector.

In the successful run here, `solve.py` reports:

- reference signature index: `0`
- subset attempt: `8`

## Recovered private key and HW_ID

Using `solve.py`, the recovered values are:

```text
d = 0xcfe6e61a5b40bb1648b0ce82722f508331702fcf2689560664f93e9cf292a8d2
HW_ID = 0x0c2e
matching_low16_count = 43
outliers = 7
```

## Verification steps

The recovery checks out in three independent ways.

### 1. Public key matches

Deriving the secp256k1 public key from `d` gives the exact compressed public key stored in `task_data.json`:

```text
0382c043d4d1e078a42e766813894d9c53042464877f7616ac34b05b3add4e747a
```

### 2. Recomputed nonces reveal the repeated low 16 bits

For each signature,

```text
k_i = (h_i + r_i d) * s_i^(-1) mod n
```

Counting `k_i & 0xffff` over all 50 signatures gives:

- `0x0c2e` appearing 43 times
- 7 remaining signatures as noisy outliers

That directly recovers `HW_ID` and confirms the nonce-generator bug.

### 3. Flag decryption works

`chal.py` encrypts the flag as:

```python
encrypted_flag = xor_stream(PLAINTEXT_FLAG, sha256(int(D_HEX, 16).to_bytes(32, "big"))).hex()
```

So once `d` is known, the decryption key is simply:

```text
SHA256(d_as_32_bytes)
```

Repeating that 32-byte digest as the XOR keystream decrypts `encrypted_flag` back to the plaintext flag.

## Flag decryption method

Algorithm:

1. Convert `d` to 32 big-endian bytes.
2. Compute `key = SHA256(d_bytes)`.
3. Repeat `key` to the ciphertext length.
4. XOR with `encrypted_flag`.

This yields:

```text
PUCTF26{y0u_4r3_1uck7_4nd_9O0d_47_5ub54mp1ing_d4102652fb095f2fDC40D346B7E02440}
```

## Final flag

```text
PUCTF26{y0u_4r3_1uck7_4nd_9O0d_47_5ub54mp1ing_d4102652fb095f2fDC40D346B7E02440}
```

## Reproduction commands

Run everything from this challenge folder.

```bash
.venv/bin/python solve.py
```

Expected output:

```text
d = 0xcfe6e61a5b40bb1648b0ce82722f508331702fcf2689560664f93e9cf292a8d2
hw_id = 3118 (0x0c2e)
matching_low16_count = 43
flag = PUCTF26{y0u_4r3_1uck7_4nd_9O0d_47_5ub54mp1ing_d4102652fb095f2fDC40D346B7E02440}
```

Optional verification of the public key and decrypted flag:

```bash
.venv/bin/python -c "import json,hashlib; from ecdsa import SECP256k1, SigningKey; task=json.load(open('task_data.json')); d=int('cfe6e61a5b40bb1648b0ce82722f508331702fcf2689560664f93e9cf292a8d2',16); print(SigningKey.from_secret_exponent(d, curve=SECP256k1).get_verifying_key().to_string('compressed').hex()==task['pubkey_compressed']); enc=bytes.fromhex(task['encrypted_flag']); key=hashlib.sha256(d.to_bytes(32,'big')).digest(); ks=(key*((len(enc)//32)+1))[:len(enc)]; print(bytes(a^b for a,b in zip(enc,ks)).decode())"
```

Optional verification of the repeated low-16 suffix count:

```bash
.venv/bin/python -c "import json,collections; task=json.load(open('task_data.json')); n=int(task['n'],16); d=int('cfe6e61a5b40bb1648b0ce82722f508331702fcf2689560664f93e9cf292a8d2',16); lows=[]; inv=lambda a: pow(a,-1,n); [lows.append((((int(x['hash'],16)+int(x['r'],16)*d)*inv(int(x['s'],16)))%n)&0xffff) for x in task['data']]; c=collections.Counter(lows); print(c.most_common(1)[0], 'outliers=', len(lows)-c.most_common(1)[0][1])"
```

## Takeaway

ECDSA nonce leakage does not need full nonce reuse to be fatal. Reusing even a fixed 16-bit suffix across enough signatures creates a strong algebraic bias, and once the noisy outliers are filtered with subset sampling, lattice/HNP methods recover the private key.
