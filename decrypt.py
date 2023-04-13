#!/usr/bin/env python3

import sys

key = b'\xac\x78\x3c\x9e\xcf\x67\xb3\x59'

filename = sys.argv[1]

def decrypter(reference):
    n = len(key)
    def decrypt(value, offset):
        nonlocal n, reference
        return value ^ key[(offset-reference)%n]

    return decrypt

with open(filename, 'rb') as f:
    s = bytearray(f.read())
    n = s[0x87]
    d = n + 0x88
    end = len(s)

    decrypt = decrypter(s.find(key))

    while d < end:
        stop = min(d + 4096, end)
        for offset in range(d, stop):
            s[offset] = decrypt(s[offset], offset)

        sys.stdout.buffer.write(bytes(s[d:stop]))
        d = stop
