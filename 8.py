#!/usr/bin/python

with open('8.txt', 'r') as f:
	lines = f.read().splitlines()

ecb_enc = []

for cip in lines:
	blocks = [cip[i:i+16] for i in xrange(0, len(cip), 16)]
	ecb = []
	count = 0
	for block in blocks:
		if block in ecb:
			count += 1
		else:
			ecb.append(block)

		# assume it's ECB encrypted if > 2 equal blocks are found
		if count > 2:
			if cip not in ecb_enc:
				ecb_enc.append(cip)

print ecb_enc
