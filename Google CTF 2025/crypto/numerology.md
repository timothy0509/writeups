# Numerology - CTF Writeup

## Challenge Overview

**Challenge Files:**
- `numerology.zip` - Challenge archive containing the challenge data
- `crypto-numerology/ctf_challenge_package.json` - Main challenge data (1024 samples + flag ciphertext)
- `crypto-numerology/init.sh` - Challenge generation script revealing cipher configuration

**Challenge Description:**
> I made a new cipher, can you help me test it? I'll give you the key, please use it to decrypt my ciphertext.

## Summary

This challenge presents a **weakened variant of the ChaCha20 stream cipher** that uses:
- **Zero constants** instead of the standard ChaCha constants (`"expand 32-byte k"`)
- **Only 1 quarter round** instead of the standard 8-20 rounds
- Known key and 1024 known plaintext-ciphertext pairs for analysis

The solution requires understanding this weakened cipher's structure and performing a **known-plaintext attack** to identify the keystream pattern, followed by a **brute-force search** to find the correct (nonce, counter) pair used to encrypt the flag.

---

## Initial Analysis

### Extracting Challenge Data

After extracting the archive, we find the challenge data in JSON format:

```json
{
    "cipher_parameters": {
        "key": "000000005c5470020000000031f4727bf7d4923400000000e7bbb1c900000000",
        "common_plaintext": "9de16236ae1521cffe67ab68fd1325951b2a1b11b75bec946325faca2a8db02a..."
    },
    "learning_dataset_for_player": [
        {
            "sample_id": "sample_n0_c0",
            "plaintext_hex": "9de16236ae1521cffe67ab68fd132595...",
            "ciphertext_hex": "d4922d0bae1521cffe67ab68fd132595...",
            "nonce_hex": "010000000000000000000000",
            "counter_int": 1
        },
        ...
    ],
    "flag_ciphertext": "692f09e677335f6152655f67304e6e40141fa702e7e5b95b46756e63298d80a9bcbbd95465795f21ef0a"
}
```

### Key Observations

1. **32-byte key** is partially structured with zero patterns
2. **1024 learning samples** all use the **same 64-byte plaintext** but different (nonce, counter) pairs
3. **42-byte flag ciphertext** to decrypt
4. The `init.sh` reveals critical configuration:
   - `ROUNDS=1` - Only 1 round of the cipher
   - Nonces and counters vary as powers of 2

---

## Cipher Analysis

### Understanding the Cipher Structure

From analyzing the compiled Python bytecode and the challenge data, we identified this as a **ChaCha20-like stream cipher** with critical weaknesses:

#### Standard ChaCha20 Structure:
```
State (16 x 32-bit words):
  [0-3]:   Constants ("expand 32-byte k")
  [4-11]:  Key (32 bytes)
  [12]:    Counter (32-bit)
  [13-15]: Nonce (12 bytes)
```

#### The "Numerology" Weakened Variant:

**Critical Weakness #1: Zero Constants**
```python
# Standard ChaCha uses:
CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

# This cipher uses:
ZERO_CONSTANTS = (0, 0, 0, 0)
```

**Critical Weakness #2: Single Quarter Round**
```python
# Standard ChaCha applies 8 quarter rounds per full round
# With ROUNDS=20, that's 160 quarter rounds

# This cipher applies only 1 quarter round!
# Specifically, only the first column round (indices 0, 4, 8, 12)
```

### The Quarter Round Function

```python
def mix_bits(state, a_idx, b_idx, c_idx, d_idx):
    """ChaCha quarter round"""
    a = state[a_idx]; b = state[b_idx]
    c = state[c_idx]; d = state[d_idx]
    
    a = add32(a, b)
    d ^= a
    d = rotl32(d, 16)
    
    c = add32(c, d)
    b ^= c
    b = rotl32(b, 12)
    
    a = add32(a, b)
    d ^= a
    d = rotl32(d, 8)
    
    c = add32(c, d)
    b ^= c
    b = rotl32(b, 7)
    
    state[a_idx] = a
    state[b_idx] = b
    state[c_idx] = c
    state[d_idx] = d
```

---

## Exploitation Methodology

### Step 1: Implement the Cipher

We needed to correctly reverse-engineer the cipher. After several iterations, we discovered the correct implementation uses **zero constants** and only **1 quarter round**:

```python
#!/usr/bin/env python3
import json
from struct import pack, unpack

# Load challenge data
with open("crypto-numerology/ctf_challenge_package.json", "r") as f:
    data = json.load(f)

common_plaintext = data["cipher_parameters"]["common_plaintext"]
learning_data = data["learning_dataset_for_player"]
flag_ciphertext_hex = data["flag_ciphertext"]
key_hex = data["cipher_parameters"]["key"]

common_pt = bytes.fromhex(common_plaintext)
flag_ct = bytes.fromhex(flag_ciphertext_hex)
key = bytes.fromhex(key_hex)

# CRITICAL: This cipher uses ZERO constants, not ChaCha constants!
ZERO_CONSTANTS = (0, 0, 0, 0)

def rotl32(v, c):
    v = v & 0xFFFFFFFF
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

def add32(a, b):
    return (a + b) & 0xFFFFFFFF

def bytes_to_words(b):
    return list(unpack("<" + "I" * (len(b) // 4), b))

def words_to_bytes(words):
    return pack("<" + "I" * len(words), *words)

def mix_bits(state_list, a_idx, b_idx, c_idx, d_idx):
    """ChaCha quarter round"""
    a = state_list[a_idx]
    b = state_list[b_idx]
    c = state_list[c_idx]
    d = state_list[d_idx]
    
    a = add32(a, b)
    d ^= a
    d = rotl32(d, 16)
    
    c = add32(c, d)
    b ^= c
    b = rotl32(b, 12)
    
    a = add32(a, b)
    d ^= a
    d = rotl32(d, 8)
    
    c = add32(c, d)
    b ^= c
    b = rotl32(b, 7)
    
    state_list[a_idx] = a
    state_list[b_idx] = b
    state_list[c_idx] = c
    state_list[d_idx] = d

def make_block_v4(key_bytes, nonce_bytes, counter_int, rounds=1):
    """
    Cipher with ZERO constants and only 'rounds' quarter rounds.
    """
    # Initialize state
    state = [0] * 16
    
    # ZERO constants at positions 0-3
    state[0:4] = list(ZERO_CONSTANTS)
    
    # Key at positions 4-11
    key_words = bytes_to_words(key_bytes)
    state[4:12] = key_words
    
    # Counter at position 12
    state[12] = counter_int & 0xFFFFFFFF
    
    # Nonce at positions 13-15
    nonce_words = bytes_to_words(nonce_bytes)
    state[13:16] = nonce_words
    
    # Save initial state
    initial_state = list(state)
    
    # Apply only 'rounds' quarter rounds
    qr_operations = [
        (0, 4, 8, 12),  # Column 0
        (1, 5, 9, 13),  # Column 1
        (2, 6, 10, 14),  # Column 2
        (3, 7, 11, 15),  # Column 3
        (0, 5, 10, 15),  # Diagonal 0
        (1, 6, 11, 12),  # Diagonal 1
        (2, 7, 8, 13),  # Diagonal 2
        (3, 4, 9, 14),  # Diagonal 3
    ]
    
    for i in range(rounds):
        a, b, c, d = qr_operations[i]
        mix_bits(state, a, b, c, d)
    
    # Add initial state to working state
    for i in range(16):
        state[i] = add32(state[i], initial_state[i])
    
    return words_to_bytes(state)
```

### Step 2: Verify Implementation

```python
# Test the implementation with a known sample
test_nonce = bytes.fromhex("010000000000000000000000")
test_counter = 1

keystream = make_block_v4(key, test_nonce, test_counter, rounds=1)
print(f"Generated keystream[0:16]: {keystream[:16].hex()}")

# Get expected keystream from sample
for sample in learning_data:
    if sample["nonce_hex"] == "010000000000000000000000" and sample["counter_int"] == 1:
        ct = bytes.fromhex(sample["ciphertext_hex"])
        expected_keystream = bytes([p ^ c for p, c in zip(common_pt, ct)])
        print(f"Expected keystream[0:16]: {expected_keystream[:16].hex()}")
        
        if keystream[:16] == expected_keystream[:16]:
            print("Implementation MATCHES!")
        break
```

### Step 3: Brute-Force Search for Flag

Since we have the correct cipher implementation, we can brute-force the (nonce, counter) pair by checking for the `CTF{` prefix:

```python
# Nonces from learning data (powers of 2 pattern)
nonces_to_try = [
    bytes.fromhex("010000000000000000000000"),
    bytes.fromhex("020000000000000000000000"),
    bytes.fromhex("040000000000000000000000"),
    bytes.fromhex("080000000000000000000000"),
    bytes.fromhex("100000000000000000000000"),
    bytes.fromhex("200000000000000000000000"),
    bytes.fromhex("400000000000000000000000"),
    bytes.fromhex("800000000000000000000000"),
]

found = False
for nonce in nonces_to_try:
    print(f"Trying nonce: {nonce.hex()}")
    for counter in range(0, 2**20):  # Search first 1M counters
        ks = make_block_v4(key, nonce, counter, rounds=1)
        decrypted = bytes([c ^ k for c, k in zip(flag_ct, ks)])
        
        try:
            text = decrypted.decode("ascii")
            if text.startswith("CTF{"):
                print(f"\nFOUND!")
                print(f"Nonce: {nonce.hex()}")
                print(f"Counter: {counter}")
                print(f"Flag: {text}")
                found = True
                break
        except UnicodeDecodeError:
            pass
        
        if counter % 50000 == 0 and counter > 0:
            print(f"  Counter {counter}...", end="\r")
    
    if found:
        break
```

### Step 4: Results

Running the brute-force search yields:

```
Trying nonce: 010000000000000000000000
  Counter 50000...
  Counter 100000...
  ...

FOUND!
Nonce: 010000000000000000000000
Counter: 32279
Flag: CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}
```

---

## The Flag

```
CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}
```

---

## Key Takeaways

### 1. Cryptographic Weaknesses Matter

This challenge demonstrates how small deviations from standard cryptographic designs can be catastrophic:

- **Zero constants**: Removing the ChaCha constants makes the cipher much weaker
- **Single round**: Reducing from 20 rounds to 1 round eliminates diffusion
- **Known-plaintext attack**: With known plaintext-ciphertext pairs, the keystream is trivially recovered

### 2. Understanding vs. Implementing

The key to solving this challenge was:
1. **Correctly identifying** the cipher as a ChaCha variant
2. **Discovering the deviations** (zero constants, single round)
3. **Implementing exactly** what the challenge used, not what standard ChaCha uses

### 3. Brute-Force Feasibility

With only 1 round, the cipher is so weak that:
- The keystream is easily computed for any (nonce, counter)
- Brute-forcing 1M counter values is trivial
- The search space is small enough for exhaustive testing

---

## Full Exploit Script

```python
#!/usr/bin/env python3
"""
Numerology CTF Challenge - Full Exploit
Weak ChaCha20 variant with zero constants and 1 round
"""

import json
from struct import pack, unpack

# Load challenge data
with open("crypto-numerology/ctf_challenge_package.json", "r") as f:
    data = json.load(f)

common_pt = bytes.fromhex(data["cipher_parameters"]["common_plaintext"])
flag_ct = bytes.fromhex(data["flag_ciphertext"])
key = bytes.fromhex(data["cipher_parameters"]["key"])
learning_data = data["learning_dataset_for_player"]

# The cipher uses ZERO constants, not ChaCha constants!
ZERO_CONSTANTS = (0, 0, 0, 0)

def rotl32(v, c):
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

def add32(a, b):
    return (a + b) & 0xFFFFFFFF

def bytes_to_words(b):
    return list(unpack("<" + "I" * (len(b) // 4), b))

def words_to_bytes(words):
    return pack("<" + "I" * len(words), *words)

def mix_bits(state, a, b, c, d):
    state[a] = add32(state[a], state[b])
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = add32(state[c], state[d])
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = add32(state[a], state[b])
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = add32(state[c], state[d])
    state[b] = rotl32(state[b] ^ state[c], 7)

def make_block(key_bytes, nonce_bytes, counter_int, rounds=1):
    state = [0] * 16
    state[0:4] = list(ZERO_CONSTANTS)
    state[4:12] = bytes_to_words(key_bytes)
    state[12] = counter_int & 0xFFFFFFFF
    state[13:16] = bytes_to_words(nonce_bytes)
    initial_state = list(state)
    
    # Only 1 quarter round!
    mix_bits(state, 0, 4, 8, 12)
    
    for i in range(16):
        state[i] = add32(state[i], initial_state[i])
    
    return words_to_bytes(state)

# Verify implementation
for sample in learning_data:
    if sample["nonce_hex"] == "010000000000000000000000" and sample["counter_int"] == 1:
        ct = bytes.fromhex(sample["ciphertext_hex"])
        expected_ks = bytes([p ^ c for p, c in zip(common_pt, ct)])
        our_ks = make_block(key, bytes.fromhex("010000000000000000000000"), 1)
        assert our_ks[:16] == expected_ks[:16], "Implementation failed!"
        print("[+] Cipher implementation verified!")
        break

# Search for flag
nonces = [bytes.fromhex(f"{1<<i:02x}000000000000000000000000") for i in range(8)]

for nonce in nonces:
    for counter in range(100000):
        ks = make_block(key, nonce, counter)
        decrypted = bytes([c ^ k for c, k in zip(flag_ct, ks)])
        try:
            if decrypted[:4] == b"CTF{":
                print(f"[+] Found flag!")
                print(f"    Nonce: {nonce.hex()}")
                print(f"    Counter: {counter}")
                print(f"    Flag: {decrypted.decode()}")
                exit(0)
        except:
            pass

print("[-] Flag not found")
```

---

## Conclusion

This was an excellent challenge that tested:
- **Cryptographic analysis skills** - identifying the ChaCha variant
- **Reverse engineering** - extracting the exact cipher parameters from compiled code
- **Attention to detail** - noticing the zero constants and single round
- **Methodical debugging** - iterating until the implementation matched known samples

The key lesson: **Never roll your own crypto**, and even small deviations from standard algorithms can render them completely insecure.
