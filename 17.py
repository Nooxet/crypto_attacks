#!/usr/bin/python2

from utils import *
import os
import random
import base64 as b64

strings = [
'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

random.seed(1337)
aes_key = ''.join(chr(random.randint(0, 255)) for i in range(16))

def encrypt_oracle():
    # choose random cipher
    random.seed(1)
    string = strings[random.randint(0, len(strings)-1)]
    plain = b64.b64decode(string)
    #print plain
    
    plain_pad = pkcs7_pad(plain, 16)
    iv = '\x00'*16
    return aes_encrypt_cbc(plain_pad, aes_key, iv), iv

def padding_oracle(cip, iv):
    p = aes_decrypt_cbc(cip, aes_key, iv)
    #print "plain:", p
    try:
        p_unpad = pkcs7_unpad(p)
        #print "unpad:", p_unpad, len(p_unpad)
    except Exception:
        return 0

    return 1


c, iv = encrypt_oracle()
# skip the last cipher block and prepend the IV.
# since to break plaintext Pn we need to edit Cn-1,
# where C-1 is the IV.
c_blocks = iv + c
print len(c_blocks)
#c_blocks = [i for i in c]
# skip the last block, since we do not need to fiddle with it
c_copy = list(c_blocks)[0:len(c_blocks)-16]
print len(c_copy)

# save the letters in ascii
letters = []

for j in range(16):
    # for the next round, change all previous values to the new
    # padding value, e.g.if we had xxx\x02\x02, now we should have 
    # xxx\x03\x03\x03
    # we get this by: ch ^ (j+1)
    for k in range(j):
        c_copy[15-k] = chr(letters[k] ^ (j+1))

    for i in range(256):
        c_copy[15-j] = chr(i)
        # skip the IV
        cc = ''.join(k for k in c_copy[16:32])
        # we need to send the flipped iv aswell, i.e., c_copy[0:16]
        if padding_oracle(cc, c_copy[0:16]) == 1:
            #print "correct at:", i
            # i ^ X = j+1 -> X = i ^ (j+1)
            ch = i^(j+1)
            letters.append(ch)
            #print "chr:", (ch)
            break

print ''.join(chr(i) for i in letters[::-1])

# save the letters in ascii
letters = []

for j in range(16):
    # for the next round, change all previous values to the new
    # padding value, e.g.if we had xxx\x02\x02, now we should have 
    # xxx\x03\x03\x03
    # we get this by: ch ^ (j+1)
    for k in range(j):
        c_copy[31-k] = chr(letters[k] ^ (j+1))

    for i in range(256):
        c_copy[31-j] = chr(i)
        # skip the IV
        cc = ''.join(k for k in c_copy[16:48])
        if padding_oracle(cc, list(c_copy[0:16])) == 1:
            #print "correct at:", i
            # i ^ X = j+1 -> X = i ^ (j+1)
            ch = i^(j+1)
            letters.append(ch)
            #print "chr:", (ch)
            break

print ''.join(chr(i) for i in letters[::-1])
"""
# break the cipher
cip = c_blocks[16:32]
plain = []
for i in range(1, 256):
    c_copy[15] = chr(ord(c_blocks[15]) ^ i)
    cc = ''.join(k for k in c_copy)
    if padding_oracle(cc, iv) == 1:
        print "correct at", i
        plain = [chr(i^1)] + plain
        break

print plain
"""
