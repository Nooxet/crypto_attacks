#!/usr/bin/python2

from utils import pkcs7_pad, aes_encrypt_ecb
from Crypto.Cipher import AES
import random
import base64 as b64
from math import ceil

with open('12.txt', 'r') as f:
    UNKNOWN = b64.b64decode(f.read())

def oracle(plain):
    random.seed(1337)
    aes_key = ''.join(chr(random.randint(0, 255)) for _ in range(16))

    prefix_nbr = random.randint(0, 50) # random count of bytes
    prefix = ''.join(chr(random.randint(0, 255)) for _ in range(prefix_nbr))

    p = prefix + plain + UNKNOWN
    p_pad = pkcs7_pad(p, 16)
    c = aes_encrypt_ecb(p_pad, aes_key)
    return c

def get_offsets():
    # create a distinct string for localizing at which offset the string is.
    # need 47 chars to be sure of covering 2 aes blocks
    marker = ''.join('A' for _ in range(47))
    cip = oracle(marker)

    blocks = [cip[i*16:(i+1)*16] for i in range(len(cip)/16)]
    # search for 2 equal, adjacent, blocks.
    # these are our marker, at a specific block offset
    for b in range(len(blocks) - 1):
        if blocks[b] == blocks[b+1]:
            block_offs = b
            cip_block = blocks[b] # this is our first block with encr. 'A's
            break
   
    # find the length of the unknown prefix.
    # add 'A' until we find our block encrypted by only 'A's.
    marker = 'A'*16
    for b in range(16):
        cip = oracle(marker)
        blocks = [cip[i*16:(i+1)*16] for i in range(len(cip)/16)]
        # we found our cipher block
        if blocks[block_offs] == cip_block:
            # the fully filled blocks (16*(b_o - 1))
            # plus the remaining bytes to fill a block (16-b)
            return 16 * (block_offs - 1) + (16 - b)
        marker += 'A'

def find_unknown(offs, block_size):
    unk_str = ''
    # the number of blocks occupied by prefix, rounded up
    block_offs = int(ceil(offs/16.0))
    # used to fill a whole block where prefix is
    pad_offs = 16 - (offs % 16)
    for block in range(9):
        for i in range(1, 17):
            test_vec = 'A' * pad_offs + 'A' * (block_size - i)
            c = oracle(test_vec)
            # get the first block of ciphertext
            # we need to take the prefix into account
            # the prefix covers "block_offs" blocks, so skip them
            c_block = c[(block+block_offs)*block_size:(block+block_offs+1)*block_size]
            # generate all possible last-byte combinations
            keydict = {}
            for j in range(256):
                k = test_vec + unk_str + chr(j)
                cc = oracle(k)[(block+block_offs)*block_size:(block+block_offs+1)*block_size]
                keydict[cc] = chr(j)

            # find the unknown byte
            unk_str += keydict[c_block]
            # break when we guessed all chars
            if block*16 + i >= 138: break

    return unk_str

offset = get_offsets()
print find_unknown(offset, block_size=16)
