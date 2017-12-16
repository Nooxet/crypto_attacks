#!/usr/bin/python

from utils import *
import base64 as b64
import itertools

#data = ''.join(i.strip() for i in open('6.in', 'r').readlines())
#raw = b64.b64decode(data)
raw = b64.b64decode(open('6.in', 'r').read())

key_dist = []
# guess keysize
for keysize in range(2, 42):
	# group text into blocks
	blocks = [raw[i:i+keysize] for i in range(0, len(raw), keysize)][0:10]
	# generate all combinations
	pairs = list(itertools.combinations(blocks, 2))
	# average the hamming distance for all combinations
	scores = [hamming_dist(i[0], i[1]) / float(keysize) for i in pairs]
	score = sum(scores) / len(scores)
	
	key_dist.append((keysize, score))

# sort w.r.t hamming distance
sort_key_dist = sorted(key_dist, key=lambda x: x[1])
print sort_key_dist

best_keysize = sort_key_dist[0][0]
print best_keysize

# divide the cipher into keysize blocks and transpose
blocks = []
for i in range(best_keysize):
	blocks.append(raw[i::best_keysize])

# break each block with single xor
key = ''
for i in blocks:
	# get the numerical key value
	intkey = break_single_byte_xor(i)[0]
	key += chr(intkey)

print key

print ''.join(chr(i) for i in repeated_key_xor(raw, key))
