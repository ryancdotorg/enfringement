#!/usr/bin/env python3
from sys import argv, stdout, stderr, version_info
from functools import partial
eprint = partial(print, file=stderr)

import io
import re
import os
import time
import requests
import argparse
import tarfile

from hashlib import md5
from urllib3.exceptions import InsecureRequestWarning

DRYRUN = True if os.environ.get('EAP_DRYRUN', False) else False

# all dbmulti bins have the core dropbear server, add (in sorted order) some
# combination of 'cli', 'conv', 'key' and 'scp' for additional functionality
#
# NOTE: if 'key' is omitted, the 'dropbearkey' command will still be handled, but
# simply print an error message an return 0 when called
DBTAR, DBBIN = 'dbmulti-armv7l.tar.xz', 'dbmulti-cli-scp'

class Registrar(dict):
    def register(self, *args, **kwargs):
        if len(args) == 1:
            if callable(args[0]):
                fn = args[0]
                self[fn.__name__] = fn
                return fn

            name = args[0]
        elif len(args) == 0 and 'name' in kwargs: name = kwargs['name']
        else: raise TypeError('Invalid argument(s)!')

        def register_name(fn):
            self[name] = fn
            return fn

        return register_name

    def dispatch(self, name, *args, **kwargs):
        return (self[name])(*args, **kwargs)


commands = Registrar()
pyver = 'Python/{0.major}.{0.minor}.{0.micro}'.format(version_info)
rqver = f'requests/{requests.__version__}'
uastr = f'Mozilla/5.0 (compatible; {pyver}; {rqver})'


def tcp_ping(host, port, timeout=3.0, *, ip6_advantage=0.2):
    import time, socket, selectors
    caddr, ip4, ip6 = None, [], []
    entries = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)

    with selectors.DefaultSelector() as sel:
        # create socket for each address
        for family, type_, _, _, saddr in entries:
            sock = socket.socket(family, type_)
            sock.settimeout(0)
            tup = (sock, saddr)
            if family == socket.AF_INET: ip4.append(tup)
            elif family == socket.AF_INET6: ip6.append(tup)

        # immediately invoked function expression; returns an elapsed time function
        elapsed = (lambda t: lambda: time.time() - t)(time.time())
        def wait_connection(iterator, deadline=timeout):
            # connect all the sockets
            for sock, saddr in iterator:
                sock.connect_ex(saddr)
                sel.register(sock, selectors.EVENT_WRITE, tup)

            # wait for events
            while deadline > elapsed():
                for key, _ in sel.select(max(0.001, deadline - elapsed())):
                    try: return key.fileobj.getpeername() # returns an ip address/port
                    except OSError as e: sel.unregister(key.fileobj)

        # favor ipv6 by trying to connect vi ipv6 slightly before ipv4
        if len(ip6): caddr = wait_connection(ip6, ip6_advantage)
        if caddr is None: caddr = wait_connection(ip4)

    # cleanup
    for sock, a in ip6 + ip4:
        try: sock.shutdown(socket.SHUT_RDWR)
        except: pass
        finally: sock.close()

    return (elapsed(), caddr)


def wait(*, url=None, **kwargs):
    ping = lambda: tcp_ping(url.host, url.port if url.port is not None else url.scheme)
    failures = -1

    while True:
        elapsed, addr = ping()
        if addr:
            if failures < 0: eprint('waiting for reboot')
            failures = 0
            time.sleep(1)
        else:
            failures += 1
            if failures > 2: break

    eprint('waiting for admin interface to return')
    while True:
        elapsed, addr = ping()
        if addr: break

def login(*, url=None, username='admin', password='admin', **kwargs):
    s = requests.Session()
    s.headers.update({'User-Agent': uastr})
    s.verify = False

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    eprint('getting login page')
    r = s.get(str(url)+'/cgi-bin/luci')

    if b'hex_md5' in r.content:
        eprint('attempting login with md5 of password')
        payload = {
            'username': username,
            'password': md5(f'{password}\n'.encode()).hexdigest(),
        }
    else:
        eprint('attempting login with cleartext password')
        payload = {'username': username, 'password': password}

    # log in
    r = s.post(str(url)+'/cgi-bin/luci', data=payload)
    # parse out base url
    m = re.match(r'(.+;stok=[0-9a-f]+)/admin/status/overview/\Z', r.url)
    if m is not None:
        eprint('got csrf token')
        return s, m.group(1)
    else:
        m = re.search(r'(/cgi-bin/luci/;stok=[0-9a-f]+)', r.content.decode())
        if m is not None:
            return s, str(url) + m.group(1)
    raise ValueError('failed to log in?')


def setcsrf(session, base):
    s = session
    eprint('syncing csrf token')
    r = s.get(f'{base}/admin/system/ajax_setCsrf')
    return s


@commands.register
def getconfig(*, session=None, base=None, url=None, outfile=None, stream=False, **kwargs):
    s = setcsrf(session, base)

    # download config
    r = s.post(
        f'{base}/admin/system/flashops', data={'backup':'\nExport'},
        stream=stream,
    )

    try:
        filename = r.headers['Content-Disposition'].split('"')[1]
        eprint(f'received: {filename}')
    except Exception as e:
        eprint(r.headers, str(r.content[0:16]))
        raise e

    if outfile:
        outfile.write(r.content)
    elif stream:
        r.raw.decode_content = True
        return r.raw
    else:
        return r.content


@commands.register
def putconfig(*, session=None, base=None, url=None, infile=None, **kwargs):
    s = setcsrf(session, base)

    success = 'upload successful, please wait ~3 minutes for restart'

    if DRYRUN:
        time.sleep(1)
        eprint(success)
        return True

    # upload config
    r = s.post(
        f'{base}/admin/system/flashops',
        files={'archive': ('overlay.tar.gz', infile, 'application/octet-stream')},
        data={'restore': 'Import'},
    )

    if 'countdownString' in r.content.decode():
        eprint(success)
        if kwargs['wait']: wait(url=url)
        return True

    return False


@commands.register
def putfirmware(*, session=None, base=None, url=None, infile=None, **kwargs):
    s = setcsrf(session, base)

    # upload firmware
    r = s.post(
        f'{base}/admin/system/flashops',
        files={'image': ('firmware.bin', infile, 'application/octet-stream')},
    )
    m = re.search(r'Checksum: <code>([0-9a-f]+)</code>', r.content.decode())
    if m is not None:
        eprint(m.group(1))
        r = s.post(f'{base}/admin/system/flashops', data={'step': 2, 'keep': ''})
        if kwargs['wait']: wait(url=url)
    else:
        raise ValueError('failed to flash?')


@commands.register
def jailbreak(*, session=None, base=None, url=None, dropbear=None, **kwargs):
    # download config
    eprint('downloading existing config')
    config = io.BytesIO(getconfig(session=session, base=base, url=url, **kwargs))

    ofile = io.BytesIO()
    with tarfile.open(None, 'w:gz', ofile) as otar:
        def patch(info, data):
            info.size = len(data)
            otar.addfile(info, io.BytesIO(data))

        with tarfile.open(None, 'r:gz', config) as itar:
            for info in itar.getmembers():
                if info.name == 'etc/shadow':
                    # fix root login vuln
                    with itar.extractfile(info) as fh:
                        data, n = re.subn(rb'root:[^:]?:', b'root:!:', fh.read())
                        if n or DRYRUN:
                            eprint(f'patched {info.name} to fix root login vuln')
                    patch(info, data)
                elif info.name == 'etc/config/dropbear':
                    # enable dropbear
                    with itar.extractfile(info) as fh:
                        data, n = re.subn(rb"(option enable ')off", rb"\1on", fh.read())
                        if n or DRYRUN:
                            eprint(f'patched {info.name} to enable ssh')
                    patch(info, data)
                elif info.isfile():
                    # add regular file
                    otar.addfile(info, itar.extractfile(info))
                else:
                    # add special file
                    otar.addfile(info)

        def mutate(info, **kwargs):
            if isinstance(info, str):
                info = tarfile.TarInfo(info)

            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mode = 0o755

            for k, v in kwargs.items():
                setattr(info, k, v)

            return info

        otar.addfile(mutate('usr', type=tarfile.DIRTYPE))
        otar.addfile(mutate('usr/sbin', type=tarfile.DIRTYPE))

        if not dropbear:
            eprint(f'injecting dropbear binary from {DBTAR}:{DBBIN}')
            dbtar = tarfile.open(DBTAR)
            info = dbtar.getmember(DBBIN)
            otar.addfile(info, dbtar.extractfile(info))
        else:
            eprint(f'injecting dropbear binary from {dropbear}')
            otar.add(dropbear, 'usr/sbin/dropbear', None, filter=mutate)

    ofile.flush()
    ofile.seek(0)

    # upload config
    eprint('uploading modified config')
    return putconfig(session=session, base=base, url=url, infile=ofile, **kwargs)


if __name__ == '__main__':
    from urllib3.util import parse_url
    from argparse import ArgumentParser, ArgumentTypeError, FileType

    def URLType(a):
        return parse_url(a)

    parser = ArgumentParser(
        usage='%(prog)s COMMAND [options]',
        description='Manage EnGenius EnSky WiFi Access Points.',
    )

    parser.add_argument(
        'command', metavar='COMMAND', choices=commands.keys(),
        help='command to perform {%(choices)s}',
    )

    parser.add_argument(
        '-u', '--username', dest='username', metavar='USER', default='admin',
        help='login username (default: admin)',
    )
    parser.add_argument(
        '-p', '--password', dest='password', metavar='PASS', default='admin',
        help='login password (default: admin)',
    )
    parser.add_argument(
        '-i', '--input', dest='infile', type=FileType('rb'), metavar='FILE',
        help='input filename (default: stdin)',
    )
    parser.add_argument(
        '-o', '--output', dest='outfile', type=FileType('wb'), metavar='FILE',
        help='output filename (default: stdout)',
    )
    parser.add_argument(
        '-a', '--url', dest='url', type=URLType, metavar='URL',
        help='AP URL',
    )
    parser.add_argument(
        '-W', '--wait', dest='wait', action='store_true',
        help='wait for access point to reboot after put operations (default: false)',
    )
    parser.add_argument(
        '--dropbear', dest='dropbear', metavar='FILE',
        help='location of dropbear binary to inject for jailbreak (default: bundled)',
    )

    args = parser.parse_args()
    args.password = os.environ.get('EAP_PASSWORD', args.password)

    # don't pass none values
    kwargs = dict(filter(lambda item: item[1] is not None, vars(args).items()))
    # extract command
    command = kwargs.pop('command')

    # fixups
    if 'wait' not in kwargs: kwargs['wait'] = False
    if 'url' in kwargs:
        url = f"{(kwargs['url'].scheme or 'http')}://{kwargs['url'].host}"
        kwargs['url'] = parse_url(url)

    # defaults
    if 'infile' not in kwargs and not stdout.isatty():
        kwargs['infile'] = os.fdopen(stdin.fileno(), "rb", closefd=False)

    if 'outfile' not in kwargs and not stdout.isatty():
        kwargs['outfile'] = os.fdopen(stdout.fileno(), "wb", closefd=False)

    # dispatch
    kwargs['session'], kwargs['base'] = login(**kwargs)
    commands.dispatch(command, **kwargs)
