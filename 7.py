#!/usr/bin/python

from utils import *
import base64

with open('7.in', 'r') as f:
	text = base64.b64decode(f.read())

print aes_decrypt_ecb(text, 'YELLOW SUBMARINE')
