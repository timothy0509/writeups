# PUCTF26 — The Secret of The Emanator of Elation

## Challenge overview

This challenge turned out to be a multi-stage forensic / crypto / file-format / vulnerability-recovery task.

At a high level, the solve path was:

1. Analyze the provided PCAP.
2. Recover the RSA-encrypted AES session key.
3. Decrypt the chat transcript.
4. Follow the hint pointing at two PNG files inside a ZIP.
5. Prove that the obvious flag is a troll / bait flag.
6. Exhaust standard steg / crypto approaches on the PNGs.
7. Notice that the environment exactly matches **Windows Snipping Tool aCropalypse**.
8. Recover the original screenshot from trailing PNG data.
9. Inspect the recovered screenshot and extract the QR code.
10. Decode the QR code to obtain the real flag.

Final flag:

`PUCTF26{Sparkl3_is_w0rld_No1_cut3_20d5770b176b0d724b1c2926658af8a7}`

---

## Files involved

Primary challenge artifacts:

- `traffic.pcapng`
- `secret_download/secret.zip`
- `secret_download/secret/secret1.png`
- `secret_download/secret/secret2.png`

Working files created during analysis:

- `secret_download/secret/trailing_raw.bin`
- `secret_download/secret/header_only.bin`
- `secret_download/secret/idat_only.bin`
- `secret_download/secret/combined_noWrappers.bin`
- `secret_download/secret/acro_decompressed.bin`
- `secret_download/secret/recovered_1920x1080.png`
- several crop / OCR / QR test images

---

## Environment and tooling used

### Core tools

- `python3`
- `Pillow` / `PIL`
- `zlib`
- `struct`
- `io`
- `hashlib`
- `base64`
- `pycryptodome` or equivalent AES/RSA helpers
- `cv2` / OpenCV
- `pyzbar`
- `pytesseract`
- standard shell utilities

### Investigation / triage tools used during exploration

- manual PNG parsing with Python
- entropy / byte-structure inspection
- OCR attempts
- image difference analysis
- bit / byte alignment testing
- QR decoding
- archive signature searches
- alternate AES mode tests
- brute-force-ish decompression alignment scans

### Tools / approaches attempted and ruled out

- standard AES-ECB decryption directly on trailing data
- AES-CBC / CFB / OFB / CTR variants
- simple XOR-based hiding
- LSB extraction
- alpha-channel extraction
- OCR on original images
- archive carving (`zip`, `7z`, signatures)
- direct zlib decompression of suspicious regions
- binwalk-style signature hunting
- steghide / general steg methods

These failures were important because they narrowed the search down to a **format-specific vulnerability recovery** problem rather than ordinary steg.

---

## Stage 1 — PCAP analysis

The first objective was to understand the encrypted chat traffic inside `traffic.pcapng`.

### Important metadata recovered from the capture

The session metadata included fields equivalent to:

- `OS_INFO: Windows 11 Pro 11.2302.20.0`
- `ENC_MODE: AES-ECB`
- an RSA public key
- an RSA-encrypted AES session key

This metadata mattered twice:

1. It told us how the chat transcript itself was encrypted: **AES-ECB**.
2. Much later, the `OS_INFO` string became the decisive clue for identifying **aCropalypse / CVE-2023-28303**.

### RSA recovery

The RSA modulus was weak enough to factor.

Recovered parameters:

- `n = 131863230739430481754033481024688741821`
- `e = 65537`
- `p = 10248643436680079621`
- `q = 12866408276776378201`

With `p` and `q`, the private exponent could be derived, then the encrypted session key could be decrypted.

### AES session key recovered

Recovered AES key:

`Sp@rkl3012345678`

Length: 16 bytes → AES-128

### Chat transcript decryption

Once the RSA layer was removed and the AES key was known, the encrypted chat messages were decrypted successfully.

Important recovered messages included:

- a hint telling us to compare two files
- a Google Drive link to a ZIP
- a bait / troll flag

Most important plaintext hint:

> "find the different of the two file, one is hide the secret!"

Important troll payload:

`PUCTF{You_got_trolled_by_Sp@rkle!}`

This looked intentionally wrong because the competition format was `PUCTF26{...}`.

That immediately suggested:

- the decrypted chat was only part of the story
- the visible bait flag was not the final answer
- the real flag had to be hidden in the downloaded files

---

## Stage 2 — ZIP extraction and initial PNG triage

The Drive link led to `secret.zip`, containing:

- `secret1.png`
- `secret2.png`

### Basic properties

#### `secret1.png`

- size: `98,134` bytes
- dimensions: `402 × 403`
- color type: RGB (`PNG color type 2`)
- DPI metadata: ~72 DPI

#### `secret2.png`

- size: `1,284,622` bytes
- dimensions: `402 × 403`
- color type: RGBA (`PNG color type 6`)
- DPI metadata: ~96 DPI

At first glance both files looked related, but `secret2.png` was suspiciously large for a `402 × 403` image.

That made `secret2.png` the primary suspect.

---

## Stage 3 — Standard image comparison

Because the hint explicitly said to compare the two files, the first wave of analysis focused on visual and structural differences.

### Pixel-level comparison

Comparisons showed:

- `47,806` pixels differed
- mean absolute difference was significant
- max per-channel differences reached `255`

So this was not just metadata noise or a tiny watermark.

### Channel inspection

The alpha channel of `secret2.png` was tested.

Finding:

- alpha channel was entirely `255`

Meaning:

- no message hidden in transparency
- no obvious alpha-layer stego

### LSB analysis

Checked:

- LSBs of `secret1.png`
- LSBs of `secret2.png`
- XOR of LSBs between both images

Result:

- no flag-like plaintext recovered
- no useful structure emerged

### OCR attempts

OCR was run on:

- `secret1.png`
- `secret2.png`
- difference renderings

Result:

- no meaningful text

At this stage, the problem no longer looked like a simple visible-text or low-bit stego challenge.

---

## Stage 4 — PNG structural analysis

The turning point started with low-level PNG chunk inspection.

### `secret2.png` contains **two IEND markers**

This was critical.

Observed:

- first `IEND` at offset `118,305`–`118,317`
- second `IEND` near the end of file

A valid PNG should normally end immediately after the first `IEND` chunk.

So `secret2.png` clearly contained trailing data after the displayed image ended.

### File layout of `secret2.png`

#### Visible PNG

From offset `0` to `118,317`, the file was a valid visible PNG containing:

- `IHDR`
- `sRGB`
- `gAMA`
- `pHYs`
- `IDAT`
- `IDAT`
- `IEND`

#### Trailing data after first `IEND`

Trailing length:

`1,166,305` bytes

That was far too large to dismiss as junk.

This data was extracted for deeper analysis.

---

## Stage 5 — Trailing data extraction and decomposition

The data after the first `IEND` was split into components.

### Extracted artifacts

- `trailing_raw.bin` — raw bytes after the first `IEND`
- `header_only.bin` — first `12,759` bytes of trailing region
- `idat_only.bin` — concatenated IDAT payload bytes from trailing region
- `combined_noWrappers.bin` — `header + trailing IDAT payloads`

### Key structural finding

The trailing region was not random garbage.

It had a strong PNG-like structure:

- `18` `IDAT` chunk markers
- evenly spaced at roughly `65,536` byte intervals
- all those `IDAT` chunks had **valid CRCs**
- ended with `IEND`

That meant the trailing data was not accidental corruption.

It was almost certainly leftover data from another valid PNG stream.

### Exact breakdown

- header-like region before first trailing `IDAT`: `12,759` bytes
- total concatenated trailing `IDAT` data: `1,153,318` bytes
- chunk wrappers and final `IEND` accounted for the rest

This was a huge clue: there appeared to be an older PNG payload preserved after the visible PNG ended.

---

## Stage 6 — Dead-end exploration phase

This challenge had a long elimination phase. These steps did **not** solve the challenge, but they were necessary to understand what the data was **not**.

### 6.1 Direct AES decryption attempts on trailing data

Because the PCAP used AES-ECB and the key had already been recovered, the first hypothesis was that the trailing blob was simply AES-encrypted hidden data.

Tried:

- AES-ECB on trailing raw bytes
- AES-ECB on aligned truncations
- alternate derivations of the same key:
  - raw key
  - MD5-derived
  - SHA-256-derived
  - uppercase / lowercase variants
  - reversed variants

Results:

- decrypted outputs remained high entropy
- no PNG signature, ZIP signature, or flag text appeared
- no useful plaintext

### 6.2 Other AES modes

Also tested:

- CBC
- CFB
- OFB
- CTR

Various IV assumptions were tried.

Results:

- no valid archives
- no valid images
- no flag strings

Conclusion:

The trailing data was almost certainly **not** just “AES-encrypted secret data using the chat key”.

### 6.3 Zlib / deflate checks

Because PNG `IDAT` data contains zlib-compressed image data, many decompression attempts were made.

Tried:

- decompressing entire trailing `IDAT` concatenation as zlib
- raw deflate attempts
- scans at many offsets
- patched headers
- combined main-image `IDAT` + trailing `IDAT`

Results:

- normal zlib decompression failed on trailing `IDAT`
- raw deflate scans did not produce a valid full image stream
- concatenating the visible PNG `IDAT` and trailing `IDAT` only decompressed the visible image; trailing bytes were ignored as excess after a complete stream

This suggested the trailing bytes were not the start of a fresh zlib stream.

### 6.4 Archive carving

Tried finding embedded:

- ZIP
- 7z
- PNG
- text blobs
- common magic values

Results:

- no useful archive signatures
- no secondary full file carved directly

### 6.5 Stego-specific tools

Tried or conceptually checked:

- steghide
- stegano-style LSB methods
- OCR over transformed images
- alpha-channel hiding
- filtered difference images

Results:

- all dead ends

### 6.6 XOR and differential transforms

Tried combinations such as:

- file XOR between `secret1.png` and `secret2.png`
- XOR between decompressed pixel streams
- XOR against extracted trailing segments

Results:

- no useful structure

---

## Stage 7 — Critical insight: this matches aCropalypse

After exhausting standard steg / crypto interpretations, the evidence strongly pointed to a different class of problem.

### Why aCropalypse fit perfectly

The decisive clue was the recovered chat metadata:

`OS_INFO: Windows 11 Pro 11.2302.20.0`

That specific Windows environment matches the vulnerable range associated with **Windows Snipping Tool aCropalypse**, commonly discussed as:

- **CVE-2023-28303** / closely related Windows Snipping Tool vulnerability class
- same family of issue as Google Pixel’s “aCropalypse” (`CVE-2023-21036`)

### What the bug does

When a screenshot is cropped / saved over the same file incorrectly, the new shorter PNG may overwrite the beginning of the old file **without truncating the original contents fully**.

Result:

- the edited / cropped PNG displays normally
- but bytes from the older, larger image remain after the first `IEND`
- enough compressed image data may survive to partially reconstruct the original screenshot

### Why `secret2.png` was a match

Everything matched this model:

- valid visible PNG ends early
- huge amount of leftover data remains after `IEND`
- trailing data still contains valid `IDAT` chunks and valid CRCs
- the environment string says Windows 11 on a vulnerable build
- the challenge hint said to “find the different”

At this point the investigation shifted completely from “decrypt hidden payload” to “recover original screenshot from an aCropalypse-corrupted PNG”.

---

## Stage 8 — Implementing aCropalypse recovery

No suitable ready-to-use package was available locally, so recovery was implemented manually in Python, based on the known public approach.

### Core idea of recovery

The preserved trailing bytes are not a clean standalone PNG.

Instead, they usually contain:

- tail bytes from the middle of an original `IDAT` chunk
- then subsequent full `IDAT` chunks
- then `IEND`

That means the original zlib stream is preserved only **from some point in the middle**.

So the task becomes:

1. reconstruct the remaining compressed `IDAT` stream
2. scan for a valid deflate block boundary
3. decompress from that boundary
4. infer the original image geometry
5. rebuild a synthetic PNG by placing recovered rows at the bottom of a canvas

### Reconstructing the leftover `IDAT` stream

Important observed structure in trailing bytes:

- the first trailing `IDAT` marker began at offset `12763` into the trailing blob
- bytes before that were interpreted as:
  - tail of previous `IDAT` data
  - CRC of previous chunk
  - length field of next chunk
  - next `IDAT`

Recovery assembled:

- partial leading `IDAT` data from `trailer[12:next_idat-8]`
- plus all subsequent full trailing `IDAT` chunk bodies
- minus the final Adler-32 footer

That produced a large compressed byte stream to scan.

### Bit-level deflate boundary scan

A normal zlib decompression from byte 0 failed because the stream started in the middle.

The fix was the classic aCropalypse trick:

- convert the bytestream into a bitstream
- generate 8 bytestream variants, one for each possible bit offset
- scan candidate start positions
- only test likely starts of non-final dynamic-Huffman deflate blocks
- prefix with a fake 32KB stored block so deflate backreferences have valid history

This is the same general method used by public aCropalypse research.

### Recovery success

The recovery code found a viable parse at:

- bit offset: `78764`

It decompressed:

- `7,521,068` bytes

That was the breakthrough.

The trailing data was confirmed to be the preserved compressed tail of a larger original screenshot.

---

## Stage 9 — Inferring the original screenshot dimensions

Once `7,521,068` bytes of decompressed scanline data were recovered, the next problem was: what are the original width / height / format?

### Strategy

For PNG scanlines:

- each row begins with a 1-byte filter value
- valid filter values are only `0` through `4`

So for candidate widths, compute:

- `stride = 1 + width * bytes_per_pixel`

Then test whether bytes at multiples of `stride` look like valid filter bytes.

### Candidate testing

Both formats were tested:

- RGB (`3` bytes per pixel)
- RGBA (`4` bytes per pixel)

Strong candidates emerged:

- RGBA width `1919`
- RGBA width `1920`
- RGB width `2560`

The most plausible was:

- **RGBA, width = 1920**

because:

- it produced valid filter bytes across all recovered rows
- it matched a standard screenshot width
- it aligned naturally with the Windows 11 screenshot hypothesis

### Height inference

For width `1920`, the row stride is:

- `1 + 1920 * 4 = 7681`

Recovered data length indicated:

- `979` complete rows
- `1369` bytes of leading partial row data

A natural original height was inferred as:

- `1080`

This fits a standard `1920 × 1080` desktop screenshot.

That means the preserved data likely corresponded to the **bottom 979 rows** of the original screenshot, with the top `101` rows lost.

---

## Stage 10 — Reconstructing the original PNG

A synthetic PNG was rebuilt with these assumptions:

- width `1920`
- height `1080`
- color type RGBA
- missing top rows filled with placeholder magenta
- recovered rows placed at the bottom

The result was saved as:

- `recovered_1920x1080.png`

### What the recovered screenshot showed

The reconstructed image was a Windows desktop screenshot.

Visible content included:

- anime desktop wallpaper
- a left-side image viewer window showing `flag.png`
- a right-side image viewer / editor window showing another image
- top rows partially corrupted / missing, which is expected in aCropalypse recovery

Most importantly, the left-side viewer clearly displayed a **QR code**.

At this point the hidden secret was no longer theoretical; it was visible.

---

## Stage 11 — OCR and screenshot interpretation

Before directly decoding the QR code, several interpretation passes were made.

### OCR findings on the recovered screenshot

OCR detected strings such as:

- `flag.png`
- `secret_ori...`

These findings were consistent with the visual layout:

- the left image was likely the real flag stored as a QR image
- the right window was another image file, perhaps the uncropped original or a related source image

### Why OCR mattered

OCR was not enough to read the flag itself, but it confirmed:

- the recovery was valid
- the screenshot content was coherent
- the left window was indeed a file called `flag.png`
- the next correct step was to **decode the QR**, not continue chasing raw bytes

---

## Stage 12 — QR extraction and final flag recovery

The user visually inspected the recovered screenshot and noticed that scanning the QR code gave the flag directly.

A direct decoder was then run against the QR screenshot attachment.

### QR decode result

Decoded content:

`PUCTF26{Sparkl3_is_w0rld_No1_cut3_20d5770b176b0d724b1c2926658af8a7}`

This matched:

- the expected competition flag format `PUCTF26{...}`
- the theme / bait name `Sparkl3`
- the overall narrative of the challenge

So this is the final correct flag.

---

## Full timeline of important findings

### Phase A — Crypto / PCAP

- recovered RSA public key parameters from PCAP
- factored modulus
- derived private key
- decrypted AES session key
- session key: `Sp@rkl3012345678`
- decrypted all chat messages successfully
- extracted bait flag and file comparison hint

### Phase B — File triage

- unpacked ZIP
- identified suspiciously oversized `secret2.png`
- measured both image formats and dimensions
- proved images differ materially

### Phase C — Standard hiding techniques eliminated

- alpha channel: no hidden payload
- LSB: no useful data
- OCR on originals: no flag
- direct AES on trailing bytes: failed
- alternate AES modes: failed
- archive carving: failed
- simple zlib decompression: failed
- XOR experiments: failed
- general steg methods: failed

### Phase D — Structural file-format insight

- found two `IEND` markers in `secret2.png`
- extracted huge trailing region after first `IEND`
- discovered valid `IDAT` chunk structure in trailing region
- confirmed valid CRCs for those chunks
- inferred preservation of original PNG data

### Phase E — Vulnerability identification

- correlated Windows build string with Snipping Tool vulnerability
- recognized aCropalypse pattern
- switched from “decrypt hidden payload” to “recover original screenshot”

### Phase F — Recovery

- rebuilt trailing `IDAT` stream
- performed bit-level deflate alignment scan
- found valid parse at bit offset `78764`
- decompressed `7,521,068` bytes
- inferred `1920 × 1080` RGBA screenshot
- reconstructed `recovered_1920x1080.png`

### Phase G — Extraction

- visually confirmed screenshot content
- located `flag.png` in recovered screenshot
- scanned / decoded QR
- obtained final flag

---

## Why the challenge is clever

This challenge mixes several disciplines in a way that intentionally wastes time unless you connect the clues correctly.

### 1. The crypto is real, but not final

The RSA and AES work is necessary.

Without decrypting the PCAP, you do not get:

- the hint
- the Drive link
- the bait flag
- the vulnerable OS version clue

But the AES key is **not** the key to the final payload. That is a deliberate trap.

### 2. The bait flag is designed to anchor you incorrectly

`PUCTF{You_got_trolled_by_Sp@rkle!}` is plausible enough to distract, but wrong enough to signal trolling if you pay attention to the event’s real flag format.

### 3. The real trick is file-format / vulnerability knowledge

The hidden data is not hidden via classic stego.

It is hidden by:

- a user workflow mistake / vulnerability artifact
- preserved old PNG data after a crop/edit/save operation

Recognizing the exact vulnerability class is the real pivot.

### 4. The hint “find the different” is literal in a non-obvious way

The “difference” is not just the visible content difference between `secret1.png` and `secret2.png`.

It is the fact that one of them was created by a vulnerable crop/edit process and therefore still contains the previous image.

---

## Lessons learned / reusable methodology

This challenge is a very good reminder of the following workflow:

### When PNGs look suspiciously large:

- check for trailing data after `IEND`
- parse chunk structures manually
- verify CRCs of suspicious chunks

### When standard steg fails:

- stop assuming classical hiding
- ask whether the artifact could come from:
  - vulnerable editors
  - partial overwrites
  - filesystem slack
  - crash artifacts
  - format-specific recovery bugs

### When a PCAP leaks environment metadata:

Treat OS / application version strings as first-class clues.

In this challenge, the Windows version string was the crucial breadcrumb.

### For aCropalypse-like PNGs:

- reconstruct leftover `IDAT` data
- scan deflate bit alignment
- use PNG filter-byte validation to infer geometry
- rebuild a synthetic image canvas from recovered bottom rows

---

## Final answer

**Flag:**

`PUCTF26{Sparkl3_is_w0rld_No1_cut3_20d5770b176b0d724b1c2926658af8a7}`

---

## Short solve summary

If you only want the compact solution path:

1. Factor the RSA modulus in the PCAP.
2. Decrypt the AES session key: `Sp@rkl3012345678`.
3. Decrypt the chat messages.
4. Ignore the troll flag.
5. Extract `secret1.png` and `secret2.png` from the ZIP.
6. Notice `secret2.png` has trailing data after the first `IEND`.
7. Correlate the Windows version with the Snipping Tool aCropalypse vulnerability.
8. Reconstruct the original PNG by recovering the preserved deflate stream.
9. Obtain the original `1920 × 1080` screenshot.
10. Scan the QR shown in `flag.png` inside that screenshot.
11. Get the final flag.

---

## Appendix — Important recovered values

### Crypto

- AES key: `Sp@rkl3012345678`
- RSA modulus: `131863230739430481754033481024688741821`
- RSA factors:
  - `10248643436680079621`
  - `12866408276776378201`

### PNG / recovery

- `secret1.png`: `402 × 403`, RGB
- `secret2.png`: `402 × 403`, RGBA
- first visible PNG end in `secret2.png`: `118,317` bytes
- trailing data size: `1,166,305` bytes
- trailing pre-IDAT header region: `12,759` bytes
- trailing full `IDAT` chunks found: `18`
- combined trailing `IDAT` payload: `1,153,318` bytes
- deflate parse found at bit offset: `78764`
- recovered decompressed bytes: `7,521,068`
- reconstructed screenshot: `1920 × 1080`

### Final

- real flag source: QR code shown in recovered screenshot
- final flag:
  - `PUCTF26{Sparkl3_is_w0rld_No1_cut3_20d5770b176b0d724b1c2926658af8a7}`