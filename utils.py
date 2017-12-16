from Crypto.Cipher import AES
import os
import random
from struct import pack

def str_to_hex(s):
    """
    Converts a hex-string into an array of integers
    """
    if len(s) % 2 != 0:
        s = s.zfill(len(s) + 1)
    
    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

def hex_to_str(h):
    """
    Converts an array of integers to a hex-string.
    """
    return ''.join(hex(i).split('x')[1].zfill(2) for i in h)

def xor(a, b):
    """
    Assumes a and b are hex values in an array.
    Returns the byte-wise xor between a and b in a hexadecimal array.
    """
    if len(a) != len(b):
        raise Exception('xor: a and b must be of equal length')
    
    return [i ^ j for i, j in zip(a, b)]

def xor_str(a, b):
    if len(a) != len(b):
        raise Exception('xor: a and b must be of equal length')
    
    return ''.join(chr(ord(i) ^ ord(j)) for i, j in zip(a, b))

def single_byte_xor(a, k):
    """
    Returns the repeated xor between the string a and the single-byte key k.
    """
    return ''.join(chr(ord(i) ^ k) for i in a)

def repeated_key_xor(a, k):
    """
    Returns the repeated xor between the string a and the key-string k.
    """
    keylen = len(k)
    return [ord(a[i]) ^ ord(k[i % keylen]) for i in range(len(a))]

def char_score(s):
    freqs = {
    'A': 0.0651738,
    'B': 0.0124248,
    'C': 0.0217339,
    'D': 0.0349835,
    'E': 0.1041442,
    'F': 0.0197881,
    'G': 0.0158610,
    'H': 0.0492888,
    'I': 0.0558094,
    'J': 0.0009033,
    'K': 0.0050529,
    'L': 0.0331490,
    'M': 0.0202124,
    'N': 0.0564513,
    'O': 0.0596302,
    'P': 0.0137645,
    'Q': 0.0008606,
    'R': 0.0497563,
    'S': 0.0515760,
    'T': 0.0729357,
    'U': 0.0225134,
    'V': 0.0082903,
    'W': 0.0171272,
    'X': 0.0013692,
    'Y': 0.0145984,
    'Z': 0.0007836,
    ' ': 0.1918182}
    score = 0
    for i in s.upper():
        if i in freqs:
            score += freqs[i]

    return score

def break_single_byte_xor(cip):
    """
    Returns the key for the single-byte xor.
    cip is the cipher string.
    """
    def key(k):
        return char_score(k[1])
    return max([(i, single_byte_xor(cip, i)) for i in range(256)], key=key)

def hamming_dist(a, b):
    if len(a) != len(b):
        raise Exception('hamming_dist: a and b must be of equal length')
    a_raw = [ord(i) for i in a]
    b_raw = [ord(i) for i in b]
    # xor and convert to binary, without the 0bxxx part
    xor = ''.join([bin(i[0] ^ i[1])[2:] for i in zip(a_raw, b_raw)])
    return xor.count('1')

def aes_encrypt_ecb(plain, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(plain)

def aes_decrypt_ecb(cipher, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(cipher)

def aes_encrypt_cbc(plain, key, iv):
    if len(key) % 16 != 0 or len(iv) != 16:
        raise Exception('aes_encrypt_cbc: key and iv must be of size 16')
    
    # pad the plaintext
    #plainpad = pkcs7_pad(plain, 16)
    blocks = [plain[i:i+16] for i in range(0, len(plain), 16)]
    
    cipher = ''
    prev_cip = iv
    for block in blocks:
        p = xor_str(block, prev_cip)
        c = aes_encrypt_ecb(p, key)
        cipher += c
        prev_cip = c
    return cipher

def aes_decrypt_cbc(cipher, key, iv):
    if len(key) % 16 != 0 or len(iv) != 16 or len(cipher) % 16 != 0:
        raise Exception('aes_decrypt_cbc: key, iv and ciphertext must be of size 16 (factor of)')

    blocks = [cipher[i:i+16] for i in xrange(0, len(cipher), 16)]

    # reverse the cbc scheme
    plain = []
    blocks = blocks[::-1]
    blocks.append(iv)
    for i in range(len(blocks) - 1):
        c = blocks[i]
        c_prev = blocks[i+1]
        p = aes_decrypt_ecb(c, key)
        p = xor_str(p, c_prev)
        plain.append(p)

    return ''.join(i for i in plain[::-1])

def pkcs7_pad(text, blocksize):
    if blocksize > 255:
        raise Exception('pkcs7_pad: block size can not be > 255 in PKCS#7')
    
    pad = blocksize - (len(text) % blocksize)
    for i in range(pad):
        text += chr(pad)
    return text

def pkcs7_unpad(text):
    pad = ord(text[-1])
    if pad == 0x00: raise Exception
    for i in text[len(text)-pad:len(text)]:
        if ord(i) != pad:
            raise Exception
    return text[0:len(text)-pad]

def aes_encrypt_ctr(plain, key, nonce):
    p_blocks = [plain[i:i+16] for i in range(0, len(plain), 16)]
    cip = []
    for ctr in range(len(p_blocks)):
        # nonce and counter in little endian
        plain = pack('<qq', nonce, ctr)
        keystream = aes_encrypt_ecb(plain, key)
        # only xor with necessary length
        p = p_blocks[ctr]
        cip.append(xor_str(keystream[0:len(p)], p))
    return ''.join(i for i in cip)

def aes_decrypt_ctr(cipher, key, nonce):
    return aes_encrypt_ctr(cipher, key, nonce)

def encryption_oracle(plain):
    """
    Encrypts with AES in eiter ECB or CBC (randomly chosen)
    """

    # generate a random AES key
    aes_key = os.urandom(16)

    # randomly append 5-10 bytes before plaintext
    pre = os.urandom(random.randint(5, 10))
    # the same after the plaintext
    post = os.urandom(random.randint(5, 10))
    p = pre + plain + post

    p_pad = pkcs7_pad(p, 16)

    mode = random.randint(0, 1)
    if mode == 0:
        # ECB mode
        return (mode, aes_encrypt_ecb(p_pad, aes_key))
    else:
        iv = os.urandom(16)
        return (mode, aes_encrypt_cbc(p_pad, aes_key, iv))

def detect_ecb(cipher):
    blocks = [cipher[i:i+16] for i in xrange(0, len(cipher), 16)]
    ecb = []
    for block in blocks:
        if block in ecb:
            return True
        else:
            ecb.append(block)
    
    return False

def ecb_oracle(plain, unknown):
    random.seed(42)
    # create a random, consistent AES key
    aes_key = ''.join(chr(random.randint(0, 255)) for _ in range(16))
    p = plain + unknown
    p_pad = pkcs7_pad(p, 16)
    c = aes_encrypt_ecb(p_pad, aes_key)
    return c

def parse_http_get(text):
    """
    Assume text is in the form
    foo=bar&baz=qux&...
    Returns a dict
    """
    obj = {}
    vals = text.split('&')
    for val in vals:
        k, v = val.split('=')
        obj[k] = v
    
    return obj

def profile_for(email):
    if '&' in email or '=' in email:
        raise Exception("profile_for: email cannot contain '&' or '='")
    
    return 'email=%s&uid=10&role=user' % email
