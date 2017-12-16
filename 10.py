#!/usr/bin/python

from utils import *
import base64 as b64

with open('10.txt', 'r') as f:
	cipher = b64.b64decode(f.read())

dec = aes_decrypt_cbc(cipher, 'YELLOW SUBMARINE', '\x00'*16)
print pkcs7_unpad(dec)
