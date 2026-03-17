# Investigative Reversing 1 - CTF Writeup

**Challenge:** Investigative Reversing 1  
**Category:** Forensics / Reverse Engineering  
**Flag:** `picoCTF{An0tha_1_8a448cb2}`  

---

## Summary

This challenge required analyzing an ELF binary and three PNG image files to recover a hidden flag. The binary reads a flag from `flag.txt` and distributes encoded/unaltered characters across three PNG files as trailer data after the IEND chunk. By reverse engineering the binary's encoding algorithm and extracting the trailer data from each PNG, the complete flag could be reconstructed.

---

## Files Provided

| File | Type | Size | Description |
|------|------|------|-------------|
| `mystery` | ELF 64-bit LSB PIE executable | 16,712 bytes | Binary that encodes and hides the flag |
| `mystery.png` | PNG image | 125,059 bytes | Contains end portion of flag in trailer |
| `mystery2.png` | PNG image | 125,045 bytes | Contains encoded first two characters |
| `mystery3.png` | PNG image | 125,051 bytes | Contains middle portion of flag in trailer |

---

## Initial Analysis

### Step 1: File Identification

```bash
file mystery mystery.png mystery2.png mystery3.png
```

Results:
- `mystery`: ELF 64-bit LSB pie executable, x86-64, dynamically linked, **not stripped**
- All PNGs: 1411x648, 8-bit/color RGB, non-interlaced

The binary being **not stripped** is significant—it means function names and symbols are preserved, making reverse engineering easier.

### Step 2: String Analysis

```bash
strings ./mystery
```

Key findings:
- `flag.txt` - The binary expects a flag file
- `mystery.png`, `mystery2.png`, `mystery3.png` - All three PNGs are referenced
- `No flag found, please make sure this is run on the server`
- `mystery.png is missing, please run this on the server`

This confirms the binary interacts with the flag file and all three PNG images.

### Step 3: PNG Trailer Analysis

PNG files end with an IEND chunk (`49 45 4E 44 AE 42 60 82`). Any data after this is trailer data and is ignored by image viewers. Checking for trailer data:

```bash
tail -c 30 mystery.png | od -A x -t x1z
tail -c 20 mystery2.png | od -A x -t x1z
tail -c 20 mystery3.png | od -A x -t x1z
```

**Results:**

**mystery.png** (16 bytes after IEND):
```
Offset: 43 46 7b 41 6e 31 5f 38 61 34 34 38 63 62 32 7d
ASCII:   C  F  {  A  n  1  _  8  a  4  4  8  c  b  2  }
```
**→ `CF{An1_8a448cb2}`**

**mystery2.png** (2 bytes after IEND):
```
Offset: 85 73
```
**→ `[0x85, 0x73]` (encoded bytes)**

**mystery3.png** (8 bytes after IEND):
```
Offset: 69 63 54 30 74 68 61 5f
ASCII:   i  c  T  0  t  h  a  _
```
**→ `icT0tha_`**

---

## Binary Reverse Engineering

### Step 4: Disassembly Analysis

```bash
objdump -d mystery
```

The `main()` function performs the following operations:

1. **File Operations (0x1185-0x121d):**
   - Opens `flag.txt` for reading
   - Opens `mystery.png`, `mystery2.png`, `mystery3.png` for appending (`"a"` mode)

2. **Flag Reading (0x121e-0x123b):**
   - Reads 26 bytes (`0x1a`) from flag.txt into buffer at `-0x30(%rbp)`

3. **Character Distribution and Encoding:**

The binary distributes flag characters across three PNG files according to a specific pattern with selective encoding:

| Flag Index | Destination | Encoding |
|------------|-------------|----------|
| flag[0] | mystery2.png | **Encoded** (see below) |
| flag[1] | mystery3.png | None |
| flag[2] | mystery3.png | None |
| flag[3] | mystery2.png | **+4** (counter from loop) |
| flag[4] | mystery.png | None |
| flag[5] | mystery3.png | None |
| flag[6-9] | mystery.png | None |
| flag[10-14] | mystery3.png | None |
| flag[15-25] | mystery.png | None |

### Step 5: Encoding Algorithm Analysis

The critical encoding for `flag[0]` occurs at addresses `0x1265-0x128d`:

```asm
1265:   0f b6 45 9d         movzbl -0x63(%rbp),%eax
1269:   83 c0 07            add    $0x7,%eax        ; var_a = c + 7
126c:   88 45 9d            mov    %al,-0x63(%rbp)
126f:   c6 45 9d 2a         movb   $0x2a,-0x63(%rbp) ; var_a = 0x2a (OVERWRITE!)
1273:   0f b6 45 9d         movzbl -0x63(%rbp),%eax
1277:   89 c2               mov    %eax,%edx
1279:   c0 ea 07            shr    $0x7,%dl         ; dl = var_a >> 7
127c:   01 d0               add    %edx,%eax        ; eax = var_a + (var_a >> 7)
127e:   d0 f8               sar    $1,%al           ; var_a = eax >> 1
1280:   88 45 9d            mov    %al,-0x63(%rbp)
1283:   0f b6 55 9f         movzbl -0x61(%rbp),%edx ; edx = original flag[0]
1287:   0f b6 45 9d         movzbl -0x63(%rbp),%eax ; eax = computed var_a
128b:   01 d0               add    %edx,%eax        ; result = flag[0] + var_a
```

**Key Insight:** At address `0x126f`, the value `0x2a` **overwrites** the previous computation (`c + 7`). This means the `+7` operation is effectively dead code!

### Step 6: Encoding Formula Derivation

Let me trace through with the constant `0x2a`:

```
var_a = 0x2a
var_a = var_a + (var_a >> 7) >> 1
      = 0x2a + (0x2a >> 7) >> 1
      = 0x2a + 0 >> 1
      = 0x2a >> 1
      = 0x15
      = 21 (decimal)

encoded = flag[0] + 21
```

**Encoding formula:** `encoded = flag_char + 21`

**Decoding formula:** `flag_char = encoded - 21`

### Step 7: Verification

Testing with mystery2.png data:
- mystery2[0] = `0x85`
- Decoded: `0x85 - 21 = 0x70 = 'p'` ✓

- mystery2[1] = `0x73`
- This is flag[3] + 4 (from counter logic)
- Decoded: `0x73 - 4 = 0x6f = 'o'` ✓

---

## Flag Reconstruction

### Step 8: Assembly Decoding Script

```python
#!/usr/bin/env python3
# Data from PNG trailers
mystery = b"CF{An1_8a448cb2}"   # 16 bytes from mystery.png
mystery2 = bytes([0x85, 0x73])  # 2 bytes from mystery2.png
mystery3 = b"icT0tha_"          # 8 bytes from mystery3.png

# Initialize flag buffer (26 characters)
flag = ["?"] * 26

# From mystery3 = "icT0tha_" → indices 1,2,5,10-14
flag[1] = "i"     # mystery3[0]
flag[2] = "c"     # mystery3[1]
flag[5] = "T"     # mystery3[2]
flag[10] = "0"    # mystery3[3]
flag[11] = "t"    # mystery3[4]
flag[12] = "h"    # mystery3[5]
flag[13] = "a"    # mystery3[6]
flag[14] = "_"    # mystery3[7]

# From mystery = "CF{An1_8a448cb2}" → indices 4,6-9,15-25
flag[4] = "C"
flag[6] = "F"
flag[7] = "{"
flag[8] = "A"
flag[9] = "n"
flag[15] = "1"
flag[16] = "_"
flag[17] = "8"
flag[18] = "a"
flag[19] = "4"
flag[20] = "4"
flag[21] = "8"
flag[22] = "c"
flag[23] = "b"
flag[24] = "2"
flag[25] = "}"

# From mystery2 = [0x85, 0x73] → indices 0, 3
flag[0] = chr(mystery2[0] - 21)  # 'p'
flag[3] = chr(mystery2[1] - 4)   # 'o'

# Construct final flag
decoded_flag = "".join(flag)
print(f"Flag: {decoded_flag}")
```

### Step 9: Execution and Verification

```bash
$ python3 decode.py

Data from PNG trailers:
  mystery.png:  b'CF{An1_8a448cb2}'
  mystery2.png: 8573 = [133, 115]
  mystery3.png: b'icT0tha_'

Testing corrected encoding:
  'p' (0x70) -> 0x85
  'i' (0x69) -> 0x7e
  'c' (0x63) -> 0x78
  'o' (0x6f) -> 0x84
  'C' (0x43) -> 0x58
  'T' (0x54) -> 0x69
  'F' (0x46) -> 0x5b
  '{' (0x7b) -> 0x90

Verification: 'p' (0x70) encodes to 0x85
Expected from mystery2[0]: 0x85
Match: True

============================================================
DECODED FLAG:
  picoCTF{An0tha_1_8a448cb2}
============================================================

Verification:
  flag[0] = 'p' -> encoded = 0x85 (expected 0x85) ✓
  flag[1] = 'i' in mystery3[0] = 'i' ✓
  flag[2] = 'c' in mystery3[1] = 'c' ✓
  flag[3] = 'o' -> +4 = 0x73 in mystery2[1] = 0x73 ✓
  flag[4] = 'C' in mystery[0] = 'C' ✓
  flag[5] = 'T' in mystery3[2] = 'T' ✓
  flag[6:10] = 'F{An' in mystery[1:5] = 'F{An' ✓
  flag[10:15] = '0tha_' in mystery3[3:8] = '0tha_' ✓
  flag[15:26] = '1_8a448cb2}' in mystery[5:16] = '1_8a448cb2}' ✓

Final Answer: picoCTF{An0tha_1_8a448cb2}
```

---

## Complete Methodology Summary

### Extraction Pipeline

```bash
# 1. Identify file types
file mystery mystery.png mystery2.png mystery3.png

# 2. Extract strings from binary
strings ./mystery | grep -E "(flag|mystery)"

# 3. Extract trailer data from PNGs
tail -c 30 mystery.png | od -A x -t x1z
tail -c 20 mystery2.png | od -A x -t x1z
tail -c 20 mystery3.png | od -A x -t x1z

# 4. Disassemble binary to understand encoding
objdump -d mystery > disassembly.txt

# 5. Run decoder script
python3 decode.py
```

### Key Reverse Engineering Insights

1. **Dead Code Detection:** The `add $0x7` instruction at 0x1269 is immediately overwritten by `movb $0x2a` at 0x126f, making it dead code.

2. **Constant Folding:** The complex bit manipulation `(var_a + (var_a >> 7)) >> 1` with `var_a = 0x2a` always evaluates to `21`.

3. **Encoding Simplification:** What appeared to be a complex multi-step encoding reduced to simple addition: `encoded = char + 21`.

4. **Distribution Pattern:** The binary writes specific character indices to each file:
   - **mystery.png:** indices 4, 6-9, 15-25 (16 chars): `CF{An1_8a448cb2}`
   - **mystery2.png:** indices 0, 3 (2 chars): encoded `p`, `o+4`
   - **mystery3.png:** indices 1, 2, 5, 10-14 (8 chars): `icT0tha_`

---

## Flag

```
picoCTF{An0tha_1_8a448cb2}
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | File type identification |
| `strings` | Extract printable strings |
| `objdump` | Binary disassembly |
| `tail` + `od` | Extract trailer data from PNGs |
| `Python 3` | Decoder script development |

---

## Lessons Learned

1. **Always check for dead code in reverse engineering** - The `+7` operation looked significant but was overwritten.

2. **PNG trailer data is a common steganography technique** - Always check for data after the IEND chunk.

3. **Binary analysis reveals the full picture** - While we could have brute-forced the encoded bytes, understanding the actual algorithm provides certainty.

4. **Not-stripped binaries make analysis easier** - Function names and symbols provide important context.
