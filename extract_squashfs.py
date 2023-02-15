#!/usr/bin/env python3

import io
import re
import sys

from functools import partial
eprint = partial(print, file=sys.stderr)

from struct import unpack

KEY = b'\xac\x78\x3c\x9e\xcf\x67\xb3\x59'
posmap = [0] * 256
decpos = (
#   0bxx00      0bxx01      0bxx10      0bxx11
    (),         (3,),       (2,),       (2,3,),     # 0b00xx
    (1,),       (1,3,),     (1,2,),     (1,2,3,),   # 0b01xx
    (0,),       (0,3,),     (0,2,),     (0,2,3,),   # 0b10xx
    (0,1,),     (0,1,3,),   (0,1,2,),   (0,1,2,3,), # 0b11xx
)
ref = {}

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
        m = re.search(r'https?://', x)
        if m is not None:
            try:
                from httpio import HttpIO
            except Exception as e:
                eprint('HttpIO unavailable:\n')
                import traceback
                traceback.print_exc()
                sys.exit(1)

            x = HttpIO(x)
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

def is_squashfs(ahead, posbits=None, offset=None):
    posbits = 0b1111 if posbits is None else posbits

    for forward in decpos[posbits]:
        header = bytearray(ahead[forward:forward+48])
        magic = bytes(header[:4])
        # could this be the magic number (encrypted or not)?
        if magic in ref:
            # grab endianness and key offset
            endian, koff = ref[magic]

            #offset = fobj.tell() + forward
            if offset is not None:
                eprint('candidate:', endian, koff, magic, offset+forward)

            if koff is not None:
                # decrypt the candidate header
                for i in range(len(header)): header[i] ^= KEY[(koff+i)%8]

            # extract some squashfs superblock data to validate
            fields = unpack(endian+'LLLLLHHHHHHQQ', header)
            magic, inode_count, modification_time, block_size = fields[0:4]
            version_major, version_minor, _, bytes_used = fields[9:13]
            compression_id = fields[5]

            # verify that we have something that looks like a squashfs header
            if magic != 1936814952: raise TypeError('bad magic (bug?)')
            if not is_power_of_2(block_size): return (None, None, 1, None)
            if compression_id > 6: return (None, None, 2, None)
            if version_major != 4: return (None, None, 3, None)
            if inode_count < 250: return (None, None, 4, None)

            return (endian, forward, koff, bytes_used)

    return (None, None, 5, None)

def search_flash(fobj):
    k = KEY + KEY
    # generate lookup table to search for a squashfs superblock
    for magic, endian in ((b'sqsh', '>'), (b'hsqs', '<')):
        # unencrypted
        ref[magic] = (endian, None)
        for i, c in enumerate(magic): posmap[c] |= 1 << i

        # encrypted
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
            endian, forward, koff, size = is_squashfs(fobj.peek(51)[:51], posbits)
            if forward is not None or koff != 5:
                eprint('is_squashfs:', endian, forward, koff, size)

            if forward is not None:
                # seek ahead as needed
                offset = fobj.seek(forward, 1)
                eprint(f'found squashfs at offset {offset}{" (encrypted)" if koff is not None else ""}')
                eprint('checking whether it is inside of an ubi image...')

                # MUST BE A POWER OF 2, AND AT LEAST 262144 (2^18)
                buf = bytearray(1<<18)

                # generate output
                yield b''
                ubi, returned = None, 0
                while True:
                    if returned >= size: return
                    n = fobj.readinto(buf)
                    if n == 0: return

                    while n < len(buf):
                        _n = fobj.readinto(buf[n:])
                        if _n == 0: break
                        n += _n

                    if koff is not None:
                        # decrypt the data block
                        #eprint(f'buf ct[{koff}] ', hexstr(buf[:8]))
                        for i in range(n): buf[i] ^= KEY[(koff+i)&7]

                    #eprint('buf pt    ', hexstr(buf[:8]))

                    if ubi is None:
                        ubi = (n, 0)
                        # look for ubi erase block headers that we need to skip
                        skip, seek = 8192, 1024
                        for p in range(0, n, seek):
                            if buf[p:p+3] == b'UBI':
                                while True:
                                    sample = buf[p+skip-8:p+skip]
                                    if sample == b'\xff\xff\xff\xff\xff\xff\xff\xff':
                                        break
                                    elif skip <= seek:
                                        raise ValueError('Failed to determine UBI parameters!')
                                    else:
                                        skip //= 2

                                if not is_power_of_2(p+skip):
                                    eprint(p, skip)
                                    raise ValueError('Failed to determine UBI parameters!')

                                ubi = (p, skip)
                                eprint(f'found ubi parameters: (data={ubi[0]}, skip={ubi[1]})')
                                for data_offset in range(0, n, p+skip):
                                    block = bytes(buf[data_offset:data_offset+p])
                                    yield block
                                    returned += ubi[0]

                                buf = bytearray(p)
                                break

                        if not ubi[1]:
                            eprint(f'ubi image not detected')
                            block = bytes(buf)
                            yield block
                            returned += n
                    elif returned + ubi[0] > size:
                        needed = max(0, size - returned)
                        block = bytes(buf[0:needed])
                        yield block
                        returned += needed
                    else:
                        block = bytes(buf[0:n])
                        yield block
                        returned += ubi[0]
                        # skip over the erase block data if present
                        if ubi[1]: erase_block = fobj.read(ubi[1])

        # advance to the next position to test
        fobj.seek(4, 1)

filename = sys.argv[1]
with buffered_reader(filename) as fobj:
    blocks = iter(())

    if fobj.peek(2)[0:2] == b'\x1f\x8b':
        # we have gzip magic, so assume this is a gzip'd tarball...
        blocks = search_tarball(fobj)
    else:
        # not a tarball, so slightly more annoying...
        blocks = search_flash(fobj)

    if next(blocks, None) == b'':
        for block in blocks:
            sys.stdout.buffer.write(block)
    else:
        eprint(f'could not find squashfs in `{filename}`')
