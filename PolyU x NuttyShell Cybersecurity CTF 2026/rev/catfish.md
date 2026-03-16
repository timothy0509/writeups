- Unpacked payload: recovered from UPX overlay at 0xf4 by parsing b_info blocks and decoding LZMA blocks with UPX’s 2-byte LZMA properties format, then rebuilding ELF LOAD segments into catfish.unpacked.
- Real check:
  - main at 0x11a0
  - validation function at 0x1470
  - success printer at 0x1590
- Logic:
  - reads input into stack buffer
  - strips newline via strcspn
  - 0x1470 checks difftime(time(NULL), saved_time) is between 25.0 and 28.0
    - constants at 0x2250 = 25.0, 0x2258 = 28.0
  - then compares input to "catch" (0x2004) with strcmp
- Why the flag is correct:
  - success path 0x1590 decodes bytes from 0x3020 by XORing each with 0x42
  - same decode loop exists at 0x1430 and 0x1590
  - encoded bytes at 0x3020 decode to the flag above
Minimal repro:
python3 solve_catfish.py
Key evidence:
1434: movzx eax, byte ptr [rip+0x2be5]   # 0x4020
1450: xor eax, 0x42
...
14bb: lea rsi, [rip+0xb42]               # 0x2004 -> "catch"
14c2: call strcmp
1492: comisd xmm0, [rip+0xdb6]           # 25.0
149c: movsd xmm1, [rip+0xdb4]            # 28.0
14a4: comisd xmm1, xmm0
Verification from reconstructed logic:
- validate("catch", 26.0) -> True
- validate("catch", 24.9) -> False
- validate("catch", 28.1) -> False
- validate("nope", 26.0) -> False
Files created in challenge dir:
- catfish.unpacked
- solve_catfish.py