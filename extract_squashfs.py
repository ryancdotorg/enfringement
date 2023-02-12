#!/usr/bin/env python3

import io
import re
import sys

from functools import partial
eprint = partial(print, file=sys.stderr)

httpio = None
import httpio
#try:
#except:
#    pass
from struct import unpack

KEY = b'\xac\x78\x3c\x9e\xcf\x67\xb3\x59'
posmap = [0] * 256
decpos = (
    (),             # 0b0000
    (3,),           # 0b0001
    (2,),           # 0b0010
    (2,3,),         # 0b0011
    (1,),           # 0b0100
    (1,3,),         # 0b0101
    (1,2,),         # 0b0110
    (1,2,3,),       # 0b0111
    (0,),           # 0b1000
    (0,3,),         # 0b1001
    (0,2,),         # 0b1010
    (0,2,3,),       # 0b1011
    (0,1,),         # 0b1100
    (0,1,3,),       # 0b1101
    (0,1,2,),       # 0b1110
    (0,1,2,3,),     # 0b1111
)
ref = {}

filename = sys.argv[1]

def hexstr(value):
    global hexstr
    from binascii import hexlify
    result = hexlify(value).decode()
    hexstr = lambda x: hexlify(x).decode()
    return result

def is_power_of_2(n):
    return n != 0 and (n & (n-1) == 0)

def buffered_reader(x, buffer_size=io.DEFAULT_BUFFER_SIZE):
    if isinstance(x, io.BufferedReader):
        if len(x.peek(0)) < buffer_size:
            try: x = x.detach()
            except UnsupportedOperation: pass
            x = io.BufferedReader(x, buffer_size)
        return x
    elif isinstance(x, io.IOBase) and x.readable():
        return io.BufferedReader(x, buffer_size)
    elif isinstance(x, (bytes, bytearray)):
        return io.BufferedReader(io.BytesIO(x), buffer_size)
    elif isinstance(x, str):
        if httpio is not None:
            m = re.search(r'https?://', x)
            if m is not None:
                x = httpio.HttpIO(x)
                x = io.BufferedReader(x, max(buffer_size, 1<<18))
                return x

        return open(x, 'rb', buffer_size)
    else:
        raise TypeError(f'Invalid argument type: `{type(x)}`')

def search_tarball(f):
    import tarfile

    with tarfile.open(fileobj=f, mode='r|gz') as tar:
        # using tar.next() instead of tar.getmembers means we don't need to seek
        for member in iter(lambda: tar.next(), None):
            with tar.extractfile(member) as f:
                magic = f.peek(4)[0:4]
                if magic in (b'sqsh', b'hsqs'):
                    eprint(f'found squashfs in tarball as `{member.name}`')
                    # generate output
                    yield b''
                    for block in iter(lambda: f.read(4096), b''):
                        yield block

                    # we're done
                    return

def search_flash(fobj):
    k = KEY + KEY
    # generate lookup table to search for a squashfs superblock
    for magic, endian in ((b'sqsh', '>'), (b'hsqs', '<')):
        ref[magic] = (endian, None)
        for p in range(8):
            # sub = magic xor key (with offset key)
            sub = bytes(map(lambda a: a[0] ^ a[1], zip(magic, k[p:])))
            for i, c in enumerate(sub): posmap[c] |= 1 << i
            ref[sub] = (endian, p)

    while True:
        # we never seek backwards on the underlying data
        try: c = fobj.peek(4)[3]
        except IndexError: break

        # check the lookup table to see whether there might be a header here
        posbits = posmap[c]
        if posbits != 0:
            # the header might be here, dig deeper
            ahead = fobj.peek(35)[:35]
            for forward in decpos[posbits]:
                header = bytearray(ahead[forward:forward+32])
                magic = bytes(header[:4])
                # could this be the magic number (encrypted or not)?
                if magic in ref:
                    # grab endianness and key offset
                    endian, koff = ref[magic]

                    #offset = fobj.tell() + forward
                    #print('candidate:', endian, koff, magic, offset, file=sys.stderr)
                    if koff is not None:
                        # decrypt the candidate header
                        for i in range(len(header)): header[i] ^= KEY[(koff+i)%8]

                    # extract some squashfs superblock data to validate
                    fields = unpack(endian+'LLLLLHHHHHH', header)
                    magic, inode_count, modification_time, block_size = fields[0:4]
                    version_major, version_minor = fields[9:11]
                    compression_id = fields[5]

                    # verify that we have something that looks like a squashfs header
                    if magic != 1936814952:
                        raise TypeError('bad magic (bug?)')
                    if not is_power_of_2(block_size): next
                    if compression_id > 6: next
                    if version_major != 4: next

                    # seek ahead as needed
                    offset = fobj.seek(forward, 1)
                    eprint(f'found squashfs at offset {offset}')

                    buf = bytearray(65536)

                    # generate output
                    yield b''
                    while True:
                        n = fobj.readinto(buf)
                        if n == 0: break
                        if koff is not None:
                            # decrypt the data block
                            for i in range(n): buf[i] ^= KEY[(koff+i)%8]
                        yield bytes(buf[0:n])
                        offset += n

                    # we're done
                    return

        fobj.seek(4, 1)

with buffered_reader(filename) as fbuf:
    blocks = iter(())

    if fbuf.peek(2)[0:2] == b'\x1f\x8b':
        # we have gzip magic, so assume this is a gzip'd tarball...
        blocks = search_tarball(fbuf)
    else:
        # not a tarball, so slightly more annoying...
        blocks = search_flash(fbuf)

    if next(blocks, None) == b'':
        for block in blocks:
            sys.stdout.buffer.write(block)
    else:
        eprint(f'could not find squashfs in `{filename}`')
