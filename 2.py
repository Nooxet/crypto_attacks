#!/usr/bin/python

import sys
from utils import *

if __name__ == '__main__':
	a = '1c0111001f010100061a024b53535009181c'
	b = '686974207468652062756c6c277320657965'

	a = str_to_hex(a)
	b = str_to_hex(b)
	res = xor(a, b)
	print ''.join(chr(i) for i in res)
