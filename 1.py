#!/usr/bin/python

import base64 as b64

from utils import *

if __name__ == '__main__':
	s = raw_input("Enter hex: ")

	h = str_to_hex(s)
	h = ''.join(chr(i) for i in h)
	print "text:", h
	print "base64:", b64.b64encode(h)
