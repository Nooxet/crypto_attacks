#!/usr/bin/python

from utils import *
import random
import os

key = os.urandom(16)

def enc_cookie(userdata):
    # remove ';' and '='
    userdata = ''.join(i for i in userdata if i != ';' and i != '=')
    data = "comment1=cooking%20MCs;userdata=" + userdata + \
        ";comment2=%20like%20a%20pound%20of%20bacon"

    # pad data
    data_pad = pkcs7_pad(data, 16)
    cip = aes_encrypt_cbc(data_pad, key, '\x00'*16)
    return cip

def dec_cookie(cip):
    userdata = aes_decrypt_cbc(cip, key, '\x00'*16)
    userdata_unpad = pkcs7_unpad(userdata)
    data = userdata_unpad.split(';')
    if 'admin=true' in data:
        return 1
    return 0

c = enc_cookie('XadminYtrue;')
c = [i for i in c]
# we want to replace X and Y to ; and =
X_semicolon = ord('X') ^ ord(';')
Y_equal = ord('Y') ^ ord('=')

# index 16 in the cipher will change plaintext at index 32, 'X'
c[16] = chr(ord(c[16]) ^ X_semicolon)
# index 22 in the cipher will change plaintext at index 38, 'Y'
c[22] = chr(ord(c[22]) ^ Y_equal)
c = ''.join(i for i in c)
print dec_cookie(c)
