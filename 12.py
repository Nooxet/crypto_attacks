#!/usr/bin/python

"""
Breaking AES-ECB mode.
Assume wee have an Oracle yielding
AES-128-ECB('own text' || 'unknown text') under an uknown key.
We may enter any "own text" and get the encrypted result.
Assume we have a block size of 16.
We can enter a text with one less byte than the block size, 15.
Let's say it is the string 'A'*15.
We know that the encrypted result in the first block is our string
plus the first byte of the unknown string.
We can generate a table of all possible strings, i.e. 'A'*15 + b,
b is taken from the ascii table.
Encrypt the strings and compare with the Oracle.
We now know the first byte of the unknown string.
Now, enter a string with 2 bytes less than block size.
The output will contain 2 bytes (last ones) from the unknown string and we know
the next to last one.
Repeat for the whole block.

When we know the secret string in the first block, repeat the above, but now
we look at the second cipher block, where we now know 15 out of 16 bytes 
(in the first round). Repeat for all blocks.
"""

from utils import *
import base64 as b64

with open('12.txt', 'r') as f:
    unknown = b64.b64decode(f.read())

# find the block size
for i in range(4, 33):
    test_input = 'A' * 2*i
    cip = ecb_oracle(test_input, unknown)
    if cip[0:i] == cip[i:2*i]:
        block_size = i
        break

def find_unknown(unknown, block_size):
    unk_str = ''
    for block in range(9):
        for i in range(1, 17):
            test_vec = 'A' * (block_size - i)
            c = ecb_oracle(test_vec, unknown)
            # get the first block of ciphertext
            c_block = c[block*block_size:(block+1)*block_size]
            # generate all possible last-byte combinations
            keydict = {}
            for j in range(256):
                k = test_vec + unk_str + chr(j)
                cc = ecb_oracle(k, '')[block*block_size:(block+1)*block_size]
                keydict[cc] = chr(j)

            # find the unknown byte
            unk_str += keydict[c_block]
            # break when we guessed all chars
            if block*16 + i >= 138: break

    return unk_str

print find_unknown(unknown, block_size)
