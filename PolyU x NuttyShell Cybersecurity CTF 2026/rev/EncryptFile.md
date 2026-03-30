# PUCTF26 - Encrypt _File (Reverse)

## Challenge Summary

We are given a single file:

- `flag.txt.encrypt`

The first 8 bytes are the magic string `MT-ENCRY`, which strongly suggests the file was encrypted by **MT Manager** since I have used this app before lol.

Goal: recover the plaintext flag in format:

`PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}`

---

## Initial Triage

The encrypted blob is only 96 bytes long and starts with:

`4d 54 2d 45 4e 43 52 59` -> `MT-ENCRY`

No local decryptor script or challenge source was provided, so the path forward is reverse engineering MT Manager’s file-encryption format.

---

## Reverse Engineering MT Manager

I used the MT Manager APK and decompiled classes to recover the exact implementation used for `.encrypt` files.

Key findings from smali:

- Container magic is `MT-ENCRY`
- PBKDF2-HMAC-SHA1 is used for key derivation
- Iteration count: `1000`
- Salt length: `8` bytes
- Password verifier length: `2` bytes
- Integrity check: HMAC-SHA1 truncated to `10` bytes
- Encryption: AES-ECB used to generate keystream blocks from a counter block (`counter_le32 || 12 zero bytes`), then XOR with ciphertext (CTR-like stream construction)

### File Format

Recovered file layout:

```
MAGIC(8) || SALT(8) || PWV(2) || CIPHERTEXT(N) || TAG(10)
```

Where:

- `PWV` is the 2-byte password verifier from derived key material
- `TAG` is first 10 bytes of `HMAC-SHA1(hmac_key, ciphertext)`

---

## Decryption Strategy

For each candidate password:

1. Compute `PBKDF2-HMAC-SHA1(password, salt, 1000, dkLen=34)`
2. Split derived bytes into:
	- `aes_key = d[0:16]`
	- `hmac_key = d[16:32]`
	- `pwv = d[32:34]`
3. Reject if derived `pwv` != stored `PWV`
4. Reject if truncated HMAC != stored `TAG`
5. If both checks pass, decrypt ciphertext with AES keystream-counter mode described above

This is very efficient because wrong passwords are discarded before decryption by verifier/HMAC.

---

## Password Recovery

I ran targeted and expanded dictionary attacks using the recovered algorithm implementation.

The correct password was:

`panic!`

Decrypting with this password produced:

`PUCTF26{Mt_Manager_ReV_1s_t0O_easy_892210d21f5e8515371170be071fdd0d}`

---

## Final Flag

`PUCTF26{Mt_Manager_ReV_1s_t0O_easy_892210d21f5e8515371170be071fdd0d}`

---

## Notes

- This challenge is correctly categorized as **reverse engineering** (with light crypto application).
- The critical step was recovering MT Manager’s exact container and key schedule from app internals.
- Once the format was known, password testing became straightforward.
