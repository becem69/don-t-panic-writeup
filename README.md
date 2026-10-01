# Don't Panic Writeup

**Category:** Reverse engineering  
**Difficulty:** Mid-hard

This challenge is distributed as a stripped 64-bit ELF binary. The goal is to
recover the input that makes the program print `correct`.

## 1. Identify the binary

```bash
file dont_panic
```

The result identifies a 64-bit x86-64 stripped ELF executable.

## 2. Check the program interface

Run it with a test argument:

```bash
./dont_panic test
```

Output:

```text
wrong
```

Run it without an argument:

```bash
./dont_panic
```

Output:

```text
usage: ./dont_panic <input>
```

The solution must therefore be supplied as one command-line argument.

## 3. Inspect readable strings

```bash
strings -a -n 4 dont_panic
```

Useful strings include:

```text
correct
wrong
```

The plaintext flag and RC4 key are not present as readable strings.

This is useful information: the program clearly has a success/failure
comparison, but the value being checked is stored as binary data rather than a
normal string. That suggests the next step should be locating references to
non-printable data from the comparison routine.

## 4. Locate the challenge-specific code

The binary is stripped, so there is no helpful `main` or `validate` symbol.
Start by searching the disassembly for the addresses of the `correct` and
`wrong` strings, then follow the nearby code that prepares the comparison.
Another useful approach is to search for unusual constants from the intended
algorithm, such as `0x100` for a 256-byte state or `0x5a`, the immediate value
used by the byte transformation.

```bash
objdump -d -Mintel dont_panic | grep -n -E '0x100|0x5a|correct|wrong'
```

The relevant routine is the code around the reference to the read-only data at
`0x3fc03`. It first loads nine bytes, transforms them, and then uses the result
as a key. Immediately after that it initializes and processes a 256-byte
state.

## 5. Inspect the validation routine

Disassemble the binary:

```bash
objdump -d -Mintel dont_panic
```

The challenge-specific routine contains code that:

1. Reads nine bytes from the read-only data section.
2. XORs every byte with `0x5a`.
3. Initializes a 256-byte state array.
4. Performs the RC4 key-scheduling algorithm.
5. Generates an RC4 keystream.
6. Compares the decrypted result with the command-line input.

### How the algorithm was identified as RC4

The identification is not a guess. Three structural observations from the
disassembly each point to RC4, and together they leave no ambiguity.

**Observation 1: a 256-byte state array initialized with 0..255**

The first loop writes each index value into the array at that same index:

```asm
mov    BYTE PTR [rsp+rdx+...],dl
inc    rdx
cmp    rdx,0x100
```

`rdx` starts at 0, is written as the value, then incremented, and the loop
runs until `rdx` reaches `0x100` (256). The result is `s[i] = i` for every
`i` from 0 to 255. That exact initialization is the first step of the RC4
KSA and is not shared with AES, DES, ChaCha20, or any other common cipher.

**Observation 2: a key-driven swap loop over that array**

Immediately after the initialization, a second loop:

- Walks the array from index 0 to 255.
- Adds a key byte to a running accumulator at each step.
- Swaps the current entry with the entry at the accumulator position.

That is the RC4 KSA body verbatim:

```python
j = 0
for i in range(256):
    j = (j + s[i] + key[i % len(key)]) & 0xff
    s[i], s[j] = s[j], s[i]
```

The combination of a 256-byte permutation mixed by a short repeating key
using index-driven swaps is unique to RC4.

**Observation 3: the output loop with two rolling indexes**

A third loop then:

- Increments one index modulo 256.
- Adds the state value at that index to a second index modulo 256.
- Swaps the two indexed entries.
- Reads a third entry using the sum of the two state values as an index.
- XORs that byte with a byte from the ciphertext.

That is the RC4 PRGA:

```python
i = 0
j = 0
for byte in ciphertext:
    i = (i + 1) & 0xff
    j = (j + s[i]) & 0xff
    s[i], s[j] = s[j], s[i]
    keystream = s[(s[i] + s[j]) & 0xff]
    output = byte ^ keystream
```

No other standard algorithm uses this exact pattern: two rolling indexes, a
swap, an indirect table lookup, and a final XOR.

All three observations come directly from reading the disassembly. The
algorithm name follows from the evidence, not the other way around.

The relevant key-byte transformation is visible in the same routine:

```asm
mov    dl,BYTE PTR [rax+rcx]
xor    dl,0x5a
mov    BYTE PTR [rsp+rax+...],dl
```

The loop counter stops at `9`, proving that the key is nine bytes long. The
instruction `xor dl,0x5a` is important: the bytes in the ELF are not the
actual key, and every byte must be XORed with `0x5a` before use.

The use of XOR for the final comparison is also why the same RC4 routine can
be used to decrypt the stored ciphertext.

## 6. Extract the encoded key and ciphertext

The disassembly contains a RIP-relative reference to address `0x3fc03`, which
falls inside `.rodata`. Dump that area:

```bash
objdump -s -j .rodata dont_panic | less
```

Near offset `0x3fc03`, the bytes are:

```text
09 2a 3b 28 11 68 6a 68 6c
cb e8 59 6b 3b 90 b2 d1 04 30 2e d3 65 4a 7d e9
65 30 54 d1 3d ff 56 b2 fa 9e af 30 97 d5
```

The boundary is confirmed by the assembly:

```asm
lea    rcx,[rip+...]        # 0x3fc03
...
cmp    rax,0x9
...
mov    dl,BYTE PTR [rax+rcx]
```

The loop reads exactly nine bytes from `0x3fc03`, so these are the encoded key:

```text
09 2a 3b 28 11 68 6a 68 6c
```

The next 30 bytes are passed to the RC4 processing loop:

```text
cb e8 59 6b 3b 90 b2 d1 04 30 2e d3 65 4a 7d e9
65 30 54 d1 3d ff 56 b2 fa 9e af 30 97 d5
```

The length of 30 is consistent with the eventual flag length, but the
important evidence is the binary's `0x1e` length passed to the processing
routine.

## 7. Recover `SparK2026`

The key is not guessed from the challenge name and is not obtained from
`strings`. It is derived directly from the two facts visible in the ELF:

1. The key source is the nine-byte sequence at `0x3fc03`.
2. Each byte is XORed with `0x5a`.

Apply the exact inverse operation:

```python
encoded_key = bytes.fromhex("092a3b2811686a686c")
key = bytes(value ^ 0x5a for value in encoded_key)
print(key)
```

This produces:

```text
SparK2026
```

The individual bytes demonstrate the reconstruction:

```text
0x09 ^ 0x5a = 0x53 = 'S'
0x2a ^ 0x5a = 0x70 = 'p'
0x3b ^ 0x5a = 0x61 = 'a'
0x28 ^ 0x5a = 0x72 = 'r'
0x11 ^ 0x5a = 0x4b = 'K'
0x68 ^ 0x5a = 0x32 = '2'
0x6a ^ 0x5a = 0x30 = '0'
0x68 ^ 0x5a = 0x32 = '2'
0x6c ^ 0x5a = 0x36 = '6'
```

This explains exactly how `SparK2026` was found from the binary.

### Why XOR with `0x5a`?

The XOR constant comes directly from the disassembly. It is not inferred from
the ciphertext or guessed from the flag format. A small search script can
locate the relevant instruction:

```python
import subprocess

disassembly = subprocess.check_output(
    ["objdump", "-d", "-Mintel", "./dont_panic"],
    text=True,
)

lines = disassembly.splitlines()

for index, line in enumerate(lines):
    if "xor" in line and "0x5a" in line:
        print("Found transformation:")
        for context in lines[max(0, index - 4):index + 3]:
            print(context)
```

The output includes the key-byte load followed by:

```asm
mov    dl,BYTE PTR [rax+rcx]
xor    dl,0x5a
mov    BYTE PTR [rsp+rax+...],dl
```

The instruction means:

```text
decoded_key_byte = encoded_key_byte XOR 0x5a
```

The nearby loop checks against `0x9`, so the transformation is applied to
exactly nine bytes. Those nine bytes are the encoded key found in `.rodata`.
Therefore the correct reconstruction is:

```python
encoded_key = bytes.fromhex("092a3b2811686a686c")
decoded_key = bytes(byte ^ 0x5a for byte in encoded_key)
print(decoded_key.decode())
```

Output:

```text
SparK2026
```

## 8. Decrypt the ciphertext

Use the following standalone script:

```python
key = bytes(value ^ 0x5a for value in bytes.fromhex(
    "092a3b2811686a686c"
))

ciphertext = bytes.fromhex(
    "cbe8596b3b90b2d104302ed3654a7de9"
    "653054d13dff56b2fa9eaf3097d5"
)

s = list(range(256))
j = 0

for i in range(256):
    j = (j + s[i] + key[i % len(key)]) & 0xff
    s[i], s[j] = s[j], s[i]

i = 0
j = 0
plaintext = bytearray()

for value in ciphertext:
    i = (i + 1) & 0xff
    j = (j + s[i]) & 0xff
    s[i], s[j] = s[j], s[i]
    keystream = s[(s[i] + s[j]) & 0xff]
    plaintext.append(value ^ keystream)

print(plaintext.decode())
```

The script mirrors the assembly:

- `s = list(range(256))` matches the state initialization.
- The first loop is the RC4 KSA.
- The second loop is the RC4 PRGA.
- `value ^ keystream` matches the binary's byte-wise XOR.

The decrypted plaintext is:

```text
Spark{wh3n_in_d0ub7_panic!_69}
```

## 9. Verify the solution

Pass the recovered plaintext to the ELF:

```bash
./dont_panic 'Spark{wh3n_in_d0ub7_panic!_69}'
```

Expected output:

```text
correct
```

A modified input is rejected:

```bash
./dont_panic 'Spark{wh3n_in_d0ub7_panic!_68}'
```

Expected output:

```text
wrong
```

The result confirms that the recovered plaintext is not merely a plausible
decryption; it is the exact value expected by the binary.

## Flag

```text
Spark{wh3n_in_d0ub7_panic!_69}
```
## Author

**becem69 😝**

Challenge designed, built, and solved by becem69 for SPARK CTF.  
If you have questions, feedback, or just want to talk reversing, feel free to reach out.
