#!/usr/bin/python

from utils import *
import base64 as b64

cipher = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
cipher = b64.b64decode(cipher)

print aes_decrypt_ctr(cipher, 'YELLOW SUBMARINE', 0)
