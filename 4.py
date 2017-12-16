#!/usr/bin/python

from utils import *

if __name__ == '__main__':
	with open('4.txt', 'r') as f:
		lines = f.read().splitlines()

	# decode from hex
	lines = [''.join(chr(j) for j in str_to_hex(i)) for i in lines]
	
	# find the text with maximum score over all ciphertexts
	def key(k):
		return char_score(k[1])
	print max([break_single_byte_xor(i) for i in lines], key=key)
