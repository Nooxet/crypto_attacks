#!/usr/bin/python

from utils import *
import os

key = os.urandom(16) # random aes key

profile = profile_for('')
p = pkcs7_pad(profile, 16)
c = aes_encrypt_ecb(p, key)

p2 = aes_decrypt_ecb(c, key)
p2 = pkcs7_unpad(p2)

# hack the profile. target: to have role=admin
# we want the 'role=' in the end of one AES block and 'user'
# in the beginning of the next, we pad with the right amount
padding = (32+4) - len(profile) # the 4 extra is the 'user'

email = 'A' * padding
hack_profile = profile_for(email)

# ciphertext length is 48, where the last 16 bytes is
# user\x0c\x0c...
prof = pkcs7_pad(hack_profile, 16)
usr_cip = aes_encrypt_ecb(prof, key)


# profile will be encoded as 'email=admin...'
# make 'admin\x0b...' be in a single AES block, thus we need to pad
# before and after.
# encrypt 'admin\x0b\x0b...' (correct padding)
email = '\x00'*10 + 'admin' + '\x0b'*11
admin_profile = profile_for(email)
admin_profile = pkcs7_pad(admin_profile, 16)
adm_cip = aes_encrypt_ecb(admin_profile, key)

#print aes_decrypt_ecb(adm_cip[16:32], key)

# the second block in adm_cip is 'admin\x0b...'
# extract this and append to usr_cip, removing 'user\x0c...'
cipher = usr_cip[:32] + adm_cip[16:32]

# now this cipher should, when decrypted, give us an admin role
plain = aes_decrypt_ecb(cipher, key)
plain = pkcs7_unpad(plain)
print plain
