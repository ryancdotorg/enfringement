#!/usr/bin/env python3

import io
import sys
import requests
import operator

__debug = False
def debug(*args, **kwarg):
    if __debug:
        if 'file' not in kwarg:
            kwarg['file'] = sys.stderr
        print(*args, **kwarg)

class HttpError(IOError):
    def __init__(self, response, message=None):
        self.response = response
        if message is None:
            self.message = f'http status {response.status_code}'
        else:
            self.message = message
        super().__init__(self.message)

class HttpIO(io.RawIOBase):
    def __init__(self, url, session=None, *, max_read=None):
        if session is None: session = requests.Session()
        self.session = session
        self._url = url
        self._pos = 0
        self._closed = False
        self._max_read = max_read
        self._seekable = True

        r = self._head()
        if 'bytes' not in r.headers.get('Accept-Ranges'):
            self._seekable = False
            raise HttpError(r, 'byte ranges not supported by server')

        self._len = int(r.headers.get('Content-Length'))
        self._mtime = r.headers.get('Last-Modified', None)
        self._etag = r.headers.get('ETag', None)

    @classmethod
    def open(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def _head(self):
        debug('_head')
        r = self.session.head(self._url, allow_redirects=True)
        if r.status_code != 200: raise HttpError(r)
        return r

    def _get(self, headers=None):
        debug('_get')
        r = self.session.get(self._url, headers=headers)
        if r.status_code not in (200, 206): raise HttpError(r)
        self._validate(r)
        return r

    def _validate(self, r):
        mtime = r.headers.get('Last-Modified', None)
        etag = r.headers.get('Etag', None)

        if mtime is not None and mtime != self._mtime:
            raise HttpError(r, f'Resource changed! (`Last-Modified` is now `{mtime}`)')

        if etag is not None and etag != self._etag:
            raise HttpError(r, f'Resource changed! (`ETag` is now `{etag}`)')


    def readall(self):
        debug(f'readall()')
        result = b''
        while True:
            block = self._read1()
            if not block: return result
            result += block

    def read(self, size=-1):
        if size < 0: return self.readall()

        debug(f'read({size})')

        result = b''
        if size == 0: return result

        while len(result) < size:
            block = self._read1(size-len(result))
            if not block: return result
            result += block

        return result

    def read1(self, size=-1):
        return self._read1(size)

    def _read1(self, size):
        debug(f'_read1({size})')
        if self._max_read and size > self._max_read:
            size = max_read

        headers = {}
        end = -1
        if size == 0:
            return b''
        elif self._pos == 0 and (size < 0 or size >= self._len):
            pass
        elif size < 0:
            end = self._len
        else:
            end = min(self._len, self._pos + size) - 1

        if self._pos > end: return b''
        headers['Range'] = f'bytes={self._pos}-{end}'

        r = self._get(headers)
        n = int(r.headers.get('Content-Length'))
        debug(f'_read1({size}) -> @{self._pos}+{n}')
        self._pos += n
        return r.content

    def readinto(self, buf):
        return self._readinto(buf, False)

    def readinto1(self, buf):
        return self._readinto(buf, True)

    def _readinto(self, buf, one):
        debug(f'_readinto({str(buf)}, {one})')
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)

        buf = buf.cast('B')

        n = len(buf)
        data = self._read1(n) if one else self.read(n)
        n = len(data)
        buf[:n] = data
        return n

    def __len__(self):
        return self._len

    def seek(self, pos, whence=0):
        debug('seek', pos, whence)
        if not self._seekable:
            raise OSError(f'seek not supported')
        if whence == 0:
            self._pos = pos
        elif whence == 1:
            self._pos += pos
        elif whence == 2:
            self._pos = self._len + pos
        else:
            raise ValueError('invalid whence')

        return self._pos

    def tell(self):
        return self._pos

    def readable(self):
        return True

    def writeable(self):
        return False

    def seekable(self):
        return self._seekable

    def close(self):
        self.session.close()
        self._closed = True

    def __getattr__(self, name):
        debug('__getattr__('+name+')')
        if name in ('truncate', 'fileno', 'write'):
            raise OSError(f'{name} not supported')

        raise AttributeError(f'object has no attribute `{name}`')

    url = property(operator.attrgetter('_url'))
    closed = property(operator.attrgetter('_closed'))
