#!/usr/bin/python

from utils import *

if __name__ == '__main__':
	cip = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
	cip = str_to_hex(cip)
	cip = ''.join(chr(i) for i in cip)
	print break_single_byte_xor(cip)
