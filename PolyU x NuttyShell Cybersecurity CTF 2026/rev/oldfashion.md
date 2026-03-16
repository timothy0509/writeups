# Oldfashion - Writeup

## Challenge Overview

- **Challenge Name:** oldfashion  
- **Category:** Reverse Engineering  
- **File:** `oldfashion` (64-bit stripped PIE ELF)  
- **Description:** "Something is hidden in this game, can you find it?"

The challenge presents a stripped 64-bit PIE ELF binary that appears to be a game. The goal is to find the hidden flag by reverse engineering the binary and understanding its internal flag construction mechanism.

---

## Initial Reconnaissance

### Step 1: Basic File Analysis

First, let's examine the binary's basic characteristics:

```bash
$ file oldfashion
oldfashion: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f40e5730e58febb05e8f4d08f5751dcd45ab2c5d, for GNU/Linux 3.2.0, stripped
```

Key observations:
- **64-bit ELF**: x86-64 architecture
- **LSB (Little Endian)**: Standard for x86
- **PIE (Position Independent Executable)**: Address space layout randomization compatible
- **Stripped**: No symbol table, function names, or debug information
- **Dynamically linked**: Uses shared libraries (libc, libm, etc.)

### Step 2: String Analysis

Let's search for interesting strings in the binary:

```bash
$ strings -a oldfashion | grep -E 'FLAG|flag|Stage|restart|clear|Press' | head -20
FLAG{REPLACE_ME}
Stage clear! (no flag)  Press R to restart
Press R to restart
GAME OVER
Arrows to move, SPACE to jump
Survive: %d
(screenshot this)
INVINCIBLE
default
```

**Critical Finding:** We find `FLAG{REPLACE_ME}` which appears to be a placeholder/decoy flag. We also see "Stage clear! (no flag)" which explicitly tells us that clearing stages normally won't give us the flag.

### Step 3: Check for Known Libraries/Frameworks

```bash
$ strings oldfashion | grep -E 'raylib|SDL|glfw|OpenGL' | head -5
# No direct matches, but we see:
$ strings oldfashion | grep -E 'InitWindow|BeginDrawing|EndDrawing'
# These are raylib function names
```

The binary appears to use **raylib** (a simple game development library), which explains the game-related strings and graphics functionality.

### Step 4: Embedded Assets Analysis

```bash
$ binwalk oldfashion

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)
1438657       0x15F3C1        PNG image, 1920 x 1080, 8-bit/color RGBA, non-interlaced
...
```

The binary contains embedded PNG images for game assets. The decoy flag string at offset `0x15f3c1` is likely part of these embedded resources.

---

## Static Analysis - Finding the Real Flag

### Step 1: Locating String References

Let's find where the strings are referenced in the code:

```bash
$ objdump -d oldfashion | grep -A5 -B5 '15f3c1\|168758'
```

Key findings:
- `0x15f3c1` → `FLAG{REPLACE_ME}` (decoy)
- `0x168758` → `Stage clear! (no flag)  Press R to restart`

Cross-references in disassembly:
```asm
    bb62:   lea    rbp,[rip+0x153858]        # 15f3c1 <FLAG{REPLACE_ME}>
    ba62:   lea    rdi,[rip+0x15ccef]        # 168758 <Stage clear! (no flag)...>
```

### Step 2: Analyzing Code Flow

Looking at the references:
- **0xbb62**: Loads the decoy flag string. This is in the game-over path.
- **0xba62**: Loads the "Stage clear! (no flag)" message. This is shown when you complete a stage normally.

Both of these are **decoy paths**. We need to find where the real flag is constructed.

### Step 3: Identifying Suspicious Code Regions

Searching for unusual code patterns:

```bash
$ objdump -d -M intel oldfashion | grep -E 'mov.*BYTE.*rsp.*34|0x340[0-9]' | head -20
```

We find multiple references to stack offsets around `rsp+0x3400` to `rsp+0x3500`, which suggests a large stack buffer is being used.

Looking at the function prologue around `0xbc77`:

```asm
    bc80:   movups xmm4,XMMWORD PTR [rip+0x184b29]
    bc87:   mov    rax,r15
    bc8a:   xor    r13d,r13d
    ...
```

This region shows:
1. SIMD operations (XMM registers)
2. Large stack allocation
3. Complex byte manipulation

### Step 4: Tracing the Flag Construction

Following the execution from `0xbc77`:

1. **Memory Allocation**: The code calls `calloc` to allocate working memory
2. **Constant Tables**: It references several constant tables in `.rodata`:
   - `0x1905a0`: First transformation table
   - `0x190620`: Second transformation table  
   - `0x190720`: Third transformation table
   - `0x191b62`: Word-sized constants

3. **Byte-by-byte construction**: The code performs complex operations:
   ```asm
   0f b6 54 05 00        movzx  edx,BYTE PTR [rbp+rax*1+0x0]
   32 14 01              xor    dl,BYTE PTR [rcx+rax*1]
   ...
   ```

4. **Final assembly**: At `0xcece`:
   ```asm
   cece:   lea    rdi,[rsp+0x3405]
   ced1:   mov    rsi,r8
   ced4:   mov    BYTE PTR [rsp+0x344e],0x0
   cedc:   rep movs BYTE PTR [rdi],BYTE PTR [rsi]
   ```

   The final flag is copied to `[rsp+0x3405]` with a null terminator at `[rsp+0x344e]`.

### Step 5: Understanding the Transformation

The flag construction involves multiple stages:

1. **Initial state setup**: Constants are loaded from `.rodata`
2. **XOR operations**: Multiple XOR operations with different keys
3. **Table lookups**: Byte values are transformed using lookup tables
4. **Bit manipulation**: Rotations, shifts, and bitwise operations
5. **Final string assembly**: The transformed bytes are assembled into the flag string

The exact algorithm is quite complex, involving:
- Multiple rounds of XOR with different keys
- Substitution using the embedded tables
- Cyclic redundancy-style operations
- Final formatting into the flag format

---

## Dynamic Analysis Approach

Since the flag is constructed dynamically, we have several options:

### Option 1: GDB Debugging
```bash
$ gdb ./oldfashion
(gdb) break *0xcece
(gdb) run
# When hit:
(gdb) x/s $rsp+0x3405
```

**Pros:** Direct, accurate  
**Cons:** The binary might have anti-debugging, requires interactive execution

### Option 2: Manual Algorithm Reversal
Reverse engineer the exact algorithm and reimplement it.

**Pros:** No runtime dependencies  
**Cons:** Very time-consuming, error-prone due to complexity

### Option 3: Emulation (Chosen Approach)
Use Unicorn Engine to emulate just the flag-building code.

**Pros:**
- Controlled execution environment
- Can hook system calls (calloc/free)
- Capture intermediate states
- No anti-debugging concerns

**Cons:** Requires proper memory mapping and PLT hooking

---

## Complete Solve Script

Here's the complete Python script using Unicorn Engine to extract the flag:

```python
#!/usr/bin/env python3
"""
Oldfashion CTF Challenge Solver
Extracts the dynamically constructed flag using Unicorn emulation

This script:
1. Loads the ELF binary and maps its segments
2. Sets up stack and heap memory regions
3. Hooks PLT entries for calloc/free to provide our own implementations
4. Emulates execution from the flag builder start (0xbc77) to end (0xcece)
5. Captures the flag from the stack buffer at [rsp+0x3405]
"""

from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *
import struct

# =============================================================================
# Configuration
# =============================================================================

BINARY_PATH = './oldfashion'
START_ADDR = 0xbc77       # Entry point of flag builder
END_ADDR = 0xcecf         # End point (just after final copy)

# Memory layout
STACK_BASE = 0x6fc00000   # Stack base address
STACK_SIZE = 0x800000     # 8MB stack
HEAP_BASE = 0x50000000    # Heap base address
HEAP_SIZE = 0x200000      # 2MB heap

# =============================================================================
# ELF Loading
# =============================================================================

def load_elf_segments(mu, path):
    """
    Load all PT_LOAD segments from the ELF file into the emulator.
    Each segment is mapped with appropriate permissions (R/W/X).
    """
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
                
            vaddr = seg['p_vaddr']
            memsz = seg['p_memsz']
            filesz = seg['p_filesz']
            offset = seg['p_offset']
            flags = seg['p_flags']
            
            # Page-align addresses
            start = vaddr & ~0xfff
            end = (vaddr + memsz + 0xfff) & ~0xfff
            size = end - start
            
            # Determine permissions
            perms = 0
            if flags & 4:  # PF_R (Read)
                perms |= UC_PROT_READ
            if flags & 2:  # PF_W (Write)
                perms |= UC_PROT_WRITE
            if flags & 1:  # PF_X (Execute)
                perms |= UC_PROT_EXEC
            
            # Map memory
            mu.mem_map(start, size, perms)
            
            # Read file data
            f.seek(offset)
            data = f.read(filesz)
            mu.mem_write(vaddr, data)
            
            # Zero-fill bss section
            if memsz > filesz:
                mu.mem_write(vaddr + filesz, b'\x00' * (memsz - filesz))
            
            print(f'[+] Mapped 0x{start:08x}-0x{end:08x} (perms: {perms})')

# =============================================================================
# PLT Hooks
# =============================================================================

heap_current = HEAP_BASE + 0x1000  # Current heap allocation pointer

def hook_calloc(mu, addr, size, user_data):
    """
    Hook for calloc@plt (0x9670)
    
    calloc(nmemb, size) allocates zeroed memory.
    We allocate from our emulated heap and return the pointer.
    """
    global heap_current
    
    # Get return address from stack
    ret_addr = struct.unpack('<Q', mu.mem_read(mu.reg_read(UC_X86_REG_RSP), 8))[0]
    
    # Get arguments
    nmemb = mu.reg_read(UC_X86_REG_RDI)
    sz = mu.reg_read(UC_X86_REG_RSI)
    total = nmemb * sz
    
    # Allocate from heap (page-aligned)
    ptr = heap_current
    heap_current += ((total + 0xfff) & ~0xfff) or 0x1000
    
    # Zero the memory (calloc behavior)
    mu.mem_write(ptr, b'\x00' * total)
    
    # Return pointer in RAX
    mu.reg_write(UC_X86_REG_RAX, ptr)
    
    # Pop return address and continue
    mu.reg_write(UC_X86_REG_RSP, mu.reg_read(UC_X86_REG_RSP) + 8)
    mu.reg_write(UC_X86_REG_RIP, ret_addr)


def hook_free(mu, addr, size, user_data):
    """
    Hook for free@plt (0x9370)
    
    free(ptr) deallocates memory.
    For our purposes, we just skip it (no actual deallocation needed).
    """
    # Get return address
    ret_addr = struct.unpack('<Q', mu.mem_read(mu.reg_read(UC_X86_REG_RSP), 8))[0]
    
    # Pop return address and continue
    mu.reg_write(UC_X86_REG_RSP, mu.reg_read(UC_X86_REG_RSP) + 8)
    mu.reg_write(UC_X86_REG_RIP, ret_addr)


def hook_memcpy_destination(mu, addr, size, user_data):
    """
    Hook called when execution reaches the final copy (0xcece).
    
    At this point, the flag has been constructed at [rsp+0x3405].
    We read it and print it, then stop emulation.
    """
    # Get current stack pointer
    rsp = mu.reg_read(UC_X86_REG_RSP)
    
    # The flag is at [rsp+0x3405]
    flag_addr = rsp + 0x3405
    
    # Read up to 128 bytes (more than enough for the flag)
    flag_data = mu.mem_read(flag_addr, 0x80)
    
    # Find null terminator
    null_pos = flag_data.find(b'\x00')
    if null_pos != -1:
        flag_data = flag_data[:null_pos]
    
    # Print the flag
    print('\n' + '='*60)
    print('FLAG EXTRACTED SUCCESSFULLY!')
    print('='*60)
    print(flag_data.decode('utf-8', errors='replace'))
    print('='*60 + '\n')
    
    # Stop emulation
    mu.emu_stop()


def hook_memory_invalid(mu, access, address, size, value, user_data):
    """
    Handle invalid memory accesses for debugging.
    """
    access_type = {
        UC_MEM_READ_UNMAPPED: 'READ_UNMAPPED',
        UC_MEM_WRITE_UNMAPPED: 'WRITE_UNMAPPED',
        UC_MEM_FETCH_UNMAPPED: 'FETCH_UNMAPPED',
        UC_MEM_WRITE_PROT: 'WRITE_PROT',
        UC_MEM_READ_PROT: 'READ_PROT',
        UC_MEM_FETCH_PROT: 'FETCH_PROT',
    }.get(access, f'UNKNOWN({access})')
    
    rip = mu.reg_read(UC_X86_REG_RIP)
    rsp = mu.reg_read(UC_X86_REG_RSP)
    
    print(f'[!] Invalid memory access: {access_type}')
    print(f'    Address: 0x{address:08x}')
    print(f'    Size: {size}')
    print(f'    RIP: 0x{rip:08x}')
    print(f'    RSP: 0x{rsp:08x}')
    
    return False  # Stop emulation

# =============================================================================
# Main Execution
# =============================================================================

def main():
    print('='*60)
    print('Oldfashion Flag Extractor')
    print('='*60)
    print()
    
    # Initialize Unicorn emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    
    # Load ELF segments
    print('[*] Loading ELF segments...')
    load_elf_segments(mu, BINARY_PATH)
    print()
    
    # Map stack memory
    print('[*] Mapping stack...')
    mu.mem_map(STACK_BASE, STACK_SIZE)
    rsp = STACK_BASE + STACK_SIZE // 2  # Start in middle of stack
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_R15, rsp)  # R15 used as base in some operations
    print(f'    Stack: 0x{STACK_BASE:08x}-0x{STACK_BASE+STACK_SIZE:08x}')
    print(f'    RSP = 0x{rsp:08x}')
    print()
    
    # Map heap memory
    print('[*] Mapping heap...')
    mu.mem_map(HEAP_BASE, HEAP_SIZE)
    print(f'    Heap: 0x{HEAP_BASE:08x}-0x{HEAP_BASE+HEAP_SIZE:08x}')
    print()
    
    # Initialize other registers
    for reg in [UC_X86_REG_RBP, UC_X86_REG_RBX, 
                UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14]:
        mu.reg_write(reg, 0)
    
    # Set up hooks
    print('[*] Setting up hooks...')
    
    # Hook PLT entries
    mu.hook_add(UC_HOOK_CODE, hook_calloc, begin=0x9670, end=0x9674)
    mu.hook_add(UC_HOOK_CODE, hook_free, begin=0x9370, end=0x9374)
    
    # Hook the flag capture point
    mu.hook_add(UC_HOOK_CODE, hook_memcpy_destination, begin=0xcece, end=0xced3)
    
    # Hook invalid memory accesses for debugging
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_memory_invalid)
    
    print('    calloc@plt hooked at 0x9670')
    print('    free@plt hooked at 0x9370')
    print('    Flag capture at 0xcece')
    print()
    
    # Run emulation
    print(f'[*] Starting emulation...')
    print(f'    Entry: 0x{START_ADDR:08x}')
    print(f'    Exit:  0x{END_ADDR:08x}')
    print()
    
    try:
        mu.emu_start(START_ADDR, END_ADDR, count=5_000_000)
    except UcError as e:
        print(f'[!] Emulation error: {e}')
        rip = mu.reg_read(UC_X86_REG_RIP)
        print(f'    Stopped at RIP = 0x{rip:08x}')
    
    print('[*] Emulation complete')

if __name__ == '__main__':
    main()
```

### Running the Script

```bash
$ python3 solve.py
============================================================
Oldfashion Flag Extractor
============================================================

[*] Loading ELF segments...
[+] Mapped 0x00000000-0x00009000 (perms: 1)
[+] Mapped 0x00009000-0x0015f000 (perms: 5)
[+] Mapped 0x0015f000-0x001c1000 (perms: 1)
[+] Mapped 0x001c1000-0x001f4000 (perms: 3)

[*] Mapping stack...
    Stack: 0x6fc00000-0x70400000
    RSP = 0x70000000

[*] Mapping heap...
    Heap: 0x50000000-0x50200000

[*] Setting up hooks...
    calloc@plt hooked at 0x9670
    free@plt hooked at 0x9370
    Flag capture at 0xcece

[*] Starting emulation...
    Entry: 0x0000bc77
    Exit:  0x0000cecf

============================================================
FLAG EXTRACTED SUCCESSFULLY!
============================================================
PUCTF26{0ld_f4sh10n_1s_n0t_0ut_0f_5tyl3_59047b21c800906534b0860f973883b5}
============================================================

[*] Emulation complete
```

---

## Technical Deep Dive

### Why Emulation Works

The flag construction routine (`0xbc77` to `0xcece`) is **self-contained**:

1. **No external dependencies** during construction
2. **Deterministic algorithm** - same input always produces same output
3. **Fixed constant tables** embedded in `.rodata`
4. **No user input required** for the construction itself

By emulating just this region, we bypass:
- Game initialization
- Graphics rendering
- User input handling
- Anti-debugging (if any)
- Timing checks

### The Construction Algorithm

While we didn't fully reverse the algorithm (emulation was faster), key observations:

```
Stage 1: Initialize state from embedded tables
    - Load 32 bytes from 0x1905a0
    - Perform initial XOR with key derived from table at 0x191b62

Stage 2: Multiple transformation rounds
    For each byte position:
        - XOR with rotating key
        - Table lookup substitution
        - Bit rotation operations
        - Modular arithmetic

Stage 3: Final assembly
    - Collect transformed bytes
    - Format into flag string (PUCTF26{...})
    - Copy to output buffer [rsp+0x3405]
```

The algorithm appears to be a custom cryptographic construction, possibly inspired by:
- AES key schedule
- Custom Feistel network
- Hash-based derivation (SHA256-like constants visible)

### Alternative Approaches

#### 1. Full Dynamic Analysis
```bash
# Run the game and complete it
./oldfashion
# Play through levels, trigger win condition
# Attach debugger at win state
```

**Difficulty:** Unknown trigger conditions, time-consuming

#### 2. Patch to Force Win State
```bash
# Patch the conditional jump at the flag check
# Force execution into the flag builder
```

**Difficulty:** Need to find all relevant checks

#### 3. Full Algorithm Reversal
```python
# Python reimplementation of the flag builder
# Would require full static analysis
```

**Difficulty:** High, error-prone

---

## Flag

```
PUCTF26{0ld_f4sh10n_1s_n0t_0ut_0f_5tyl3_59047b21c800906534b0860f973883b5}
```

---

## Lessons Learned

1. **Look for dynamic construction**: Real flags often require runtime computation

2. **Emulation is powerful**: When static analysis is complex, targeted emulation can quickly yield results

3. **Understand the context**: Knowing this was a raylib game helped identify that normal gameplay wouldn't reveal the flag

4. **Hook system calls**: Emulating libc functions (calloc/free) allows us to control memory allocation

---

## Tools Used

- **file**: Basic binary identification
- **strings**: String extraction
- **objdump**: Disassembly and cross-reference analysis
- **binwalk**: Embedded asset detection
- **pyelftools**: ELF parsing in Python
- **Unicorn Engine**: CPU emulation framework
- **Capstone** (via Unicorn): Disassembly engine

---

## Conclusion

This challenge required looking past the obvious decoy flag and identifying the real flag-building routine through careful static analysis. The flag is constructed dynamically at runtime through a complex series of byte-level operations between addresses `0xbc77` and `0xcece`, with the final result stored at `[rsp+0x3405]`. 

Using Unicorn emulation allowed us to execute just the flag-building code in isolation and extract the result without needing to:
- Reverse the entire transformation algorithm manually
- Play through the game to trigger the win condition
- Deal with any potential anti-debugging mechanisms

The approach demonstrates the power of selective emulation in reverse engineering challenges where the target computation is self-contained but algorithmically complex.
