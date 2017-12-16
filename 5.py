#!/usr/bin/python

from utils import *

if __name__ == '__main__':
	key = 'ICE'

	# read each line
	with open('5.in', 'r') as f:
		lines = f.read().strip()
		print lines

#	for line in lines:
	print hex_to_str(repeated_key_xor(lines, key))

# repeating XOR under key
#xor = [ord(lines[i]) ^ ord(key[i % len(key)]) for i in range(len(lines))]
#print ''.join(hex(i).split('x')[1].zfill(2) for i in xor)
