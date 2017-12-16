#!/usr/bin/python

from utils import *

with open('11.txt', 'r') as f:
	plain = f.read()

# count how many correct answers
count = 0
for i in range(1000):
	mode, cip = encryption_oracle(plain)
	output = detect_ecb(cip)
	if (output == True and mode == 0) or (output == False and mode == 1):
		count += 1

print (count)
