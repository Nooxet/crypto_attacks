#!/usr/bin/python

from utils import *

# correct
msg = 'A'*14 + '\x02\x02'
try:
    pkcs7_unpad(msg)
except Exception:
    print "WRONG"

# wrong
msg = 'A'*14 + '\x03\x03'
try:
    pkcs7_unpad(msg)
    print "WRONG"
except Exception:
    pass

# wrong
msg = 'A'*15 + '\x00'
try:
    pkcs7_unpad(msg)
    print "WRONG"
except Exception:
    pass
