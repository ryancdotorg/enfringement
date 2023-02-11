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

class HttpIO(io.IOBase):
    def __init__(self, url, session=None):
        if session is None: session = requests.Session()
        self.session = session
        self._url = url
        self._pos = 0
        self._debug = 0
        self._open = True
        self._seekable = True
        r = self._head()
        if 'bytes' not in r.headers.get('Accept-Ranges'):
            self._seekable = False
            raise HttpError(r, 'byte ranges not supported by server')
        self._len = int(r.headers.get('Content-Length'))

    def _head(self):
        r = self.session.head(self._url)
        if r.status_code != 200: raise HttpError(r)
        return r

    def _get(self, headers=None):
        r = self.session.get(self._url, headers=headers)
        if r.status_code not in (200, 206): raise HttpError(r)
        return r

    def read(self, size=-1):
        debug('read')
        return self.read1(size)

    def read1(self, size=-1):
        debug(f'read1({size})')
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
        debug(f'read1({size}) -> @{self._pos}+{n}')
        self._pos += n
        #debug('->', len(r.content), r.content)
        return r.content

    def readinto(self, buf):
        debug('readinto')
        return self.readinto1(buf)

    def readinto1(self, buf):
        debug('readinto1')
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)

        buf = buf.cast('B')
        data = self.read(len(buf))
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
        self._open = False

    @property
    def closed(self):
        return not self._open

    def __getattr__(self, name):
        debug('__getattr__('+name+')')
        if name in ('truncate', 'fileno', 'write'):
            raise OSError(f'{name} not supported')

        raise AttributeError(f'object has no attribute `{name}`')

    url = property(operator.attrgetter('_url'))
