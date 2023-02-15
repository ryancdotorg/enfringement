#!/usr/bin/env python3
from sys import argv, stdin, stdout, stderr, version_info
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

pyver = 'Python/{0.major}.{0.minor}.{0.micro}'.format(version_info)
rqver = f'requests/{requests.__version__}'
uastr = f'Mozilla/5.0 (compatible; {pyver}; {rqver})'

VERBOSE = False
def vprint(*args, **kwargs):
    if VERBOSE: print(*args, file=stderr, **kwargs)

DRYRUN = True if os.environ.get('EAP_DRYRUN', False) else False

# all dbmulti bins have the core dropbear server, add (in sorted order) some
# combination of 'cli', 'conv', 'key' and 'scp' for additional functionality
#
# NOTE: if 'key' is omitted, the 'dropbearkey' command will still be handled, but
# simply print an error message an return 0 when called
DBTAR, DBBIN = 'dbmulti-armv7l.tar.xz', 'dbmulti-cli-scp'

# mappings from firmware dumps
HWID = {
    'EWSAP':            '00000000',     'EWS370AP':         '0101007B',
    'EWS371AP':         '0101007C',     'EWS870AP':         '0101007D',
    'EWS871AP':         '0101007E',     'EAP2200':          '01010080',
    'EMR5000':          '01010080',     'EWS355AP':         '0101008A',
    'EWS550AP':         '0101008A',     'ESR580':           '0101008d',
    'EWS330AP':         '01010097',     'EAP1250':          '01010098',
    'ENS202EXTv2':      '01010099',     'ENS202v2':         '0101009A',
    'EMD1':             '0101009C',     'EAP1300':          '0101009D',
    'EAP1300EXT':       '0101009E',     'ENS620EXT':        '010100A4',
    'ENH1350EXT':       '010100A6',     'EMD2':             '010100A9',
    'EMD11':            '010100B3',     'ENS500-AC':        '010100B9',
    'ENS500EXT-AC':     '010100BA',     'EnStation5-AC':    '010100BB',
    'EAP2250':          '010100BD',     'EWS385AP':         '010100BE',
    'EnStationACv2':    '01010103',     'ENH500v3':         '01010104',
}

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

def getdocstr(fn):
    import inspect
    return inspect.getdoc(fn)

def mutate(info, **kwargs):
    if isinstance(info, str):
        info = tarfile.TarInfo(info)
        if 'type' in kwargs:
            info.type = kwargs['type']
        elif 'linkname' in kwargs:
            info.type = tarfile.SYMTYPE

    info.uid = info.gid = 0
    info.uname = info.gname = 'root'
    if info.issym():
        info.mode = 0o777
    else:
        info.mode &= 0o755
        info.mode |= 0o111 if info.isdir() else 0

    for k, v in kwargs.items():
        setattr(info, k, v)

    return info

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

        # favor ipv6 by trying to connect via ipv6 slightly before ipv4
        if len(ip6): caddr = wait_connection(ip6, ip6_advantage)
        if caddr is None: caddr = wait_connection(ip4)

    # cleanup
    for sock, a in ip6 + ip4:
        try: sock.shutdown(socket.SHUT_RDWR)
        except: pass
        finally: sock.close()

    return (elapsed(), caddr)

def wait(*, url, **kwargs):
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

def login(*, url, username='admin', password='admin', **kwargs):
    s = requests.Session()
    s.headers.update({'User-Agent': uastr})
    s.verify = False

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    vprint('getting login page')
    r = s.get(str(url)+'/cgi-bin/luci')

    if b'hex_md5' in r.content:
        vprint('attempting login with md5 of password')
        payload = {
            'username': username,
            'password': md5(f'{password}\n'.encode()).hexdigest(),
        }
    else:
        vprint('attempting login with cleartext password')
        payload = {'username': username, 'password': password}

    # log in
    r = s.post(str(url)+'/cgi-bin/luci', data=payload)
    # parse out base url
    m = re.match(r'(.+;stok=[0-9a-f]+)/admin/status/overview/\Z', r.url)
    if m is not None:
        vprint('got csrf token')
        return s, m.group(1)
    else:
        m = re.search(r'(/cgi-bin/luci/;stok=[0-9a-f]+)', r.content.decode())
        if m is not None:
            return s, str(url) + m.group(1)
    raise ValueError('failed to log in?')

def setcsrf(session, base):
    s = session
    vprint('syncing csrf token')
    r = s.get(f'{base}/admin/system/ajax_setCsrf')
    return s

@commands.register
def getstatus(*, session, base, url, outfile=None, **kwargs):
    '''get the device's network status'''

    s = setcsrf(session, base)

    r = s.get(f'{base}/admin/status/overview?status=1')

    if outfile:
        outfile.write(r.content)
    else:
        print(r.content.decode())

    return r.content

@commands.register
def getmac(*, session, base, url, outfile=None, **kwargs):
    '''get the device's model number and mac address'''

    s = setcsrf(session, base)

    r = s.get(f'{base}/admin/status/overview/')
    html = r.content

    # no, you cannot parse html with regular expressions, but this'll work...
    pattern  = rb'<div\s+[^>]*\bclass="PIE"[^>]+>\s*'
    pattern += rb'<div[^>]*>\s*([^<]+)\s*</div>\s*'
    pattern += rb'<div[^>]*>\s*([^<]+)\s*</div>\s*'
    pattern += rb'.+<td\s+[^>]*\bmyid="Device_Serial_Number_text"[^>]*>([0-9A-F]+)</td>'
    pattern += rb'.+<td\s+[^>]*\bid="mac_lan"[^>]*>([0-9A-F:]+)</td>'
    m = re.search(pattern, html, flags=re.MULTILINE|re.DOTALL)
    if m is not None:
        info = tuple(map(bytes.decode, m.groups()))
        model = info[0]
        desc = info[1]
        serial = info[2]
        mac = info[3]

        ofile = io.StringIO()
        ofile.write("# DON'T TOUCH THESE!\n")
        # add hwid if the model is recognized
        if model in HWID:
            ofile.write(f"hwid = {HWID[model]}\n")
        ofile.write(f"modelname = {model}\n")
        ofile.write(f"macaddr = {mac}\n")
        ofile.write(f"serial = {serial}\n")
        m = re.search(rb'\s*var\s+firmwareVersion\s*=\s*["\']([0-9.]+)["\']', html)
        if m is not None:
            ofile.write(f"fwver = {m.group(1).decode()}\n")
        ofile.write("\n# Can edit from here.")
        ofile.flush()
        ofile.seek(0)

        if outfile:
            outfile.write(ofile.getvalue().encode()+b'\n')
        else:
            print(ofile.getvalue())

        return True
    else:
        return False

@commands.register
def getconfig(*, session, base, url, outfile=None, stream=False, **kwargs):
    '''download the current config'''

    s = setcsrf(session, base)

    # download config
    r = s.post(
        f'{base}/admin/system/flashops', data={'backup':'\nExport'},
        stream=stream,
    )

    try:
        filename = r.headers['Content-Disposition'].split('"')[1]
        vprint(f'received: {filename}')
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
def putconfig(*, session, base, url, infile=None, **kwargs):
    '''upload a config bundle'''

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
def putfirmware(*, session, base, url, infile=None, **kwargs):
    '''flash a firmware file'''

    s = setcsrf(session, base)

    # upload firmware
    r = s.post(
        f'{base}/admin/system/flashops',
        files={'image': ('firmware.bin', infile, 'application/octet-stream')},
    )
    m = re.search(r'Checksum: <code>([0-9a-f]+)</code>', r.content.decode())
    if m is not None:
        vprint(m.group(1))
        r = s.post(f'{base}/admin/system/flashops', data={'step': 2, 'keep': ''})
        if kwargs['wait']: wait(url=url)
    else:
        raise ValueError('failed to flash?')

@commands.register
def gethwid(*, session, base, url, outfile=None, **kwargs):
    '''extract device's hardware info to a template config'''

    # download config
    vprint('downloading existing config')
    config = io.BytesIO(getconfig(session=session, base=base, url=url, **kwargs))

    ofile = io.StringIO()

    with tarfile.open(None, 'r:gz', config) as itar:
        ofile.write("# DON'T TOUCH THESE!\n")
        for info in itar.getmembers():
            if info.name == 'etc/config/sysProductInfo':
                with itar.extractfile(info) as fh:
                    for line in map(lambda x: x.decode().rstrip(), fh):
                        m = re.fullmatch(r"\t+option\s+(\w+)\s+'?([^']*)'?", line)
                        if m is not None:
                            k, v = m.group(1), m.group(2)
                            if k == 'HWID':              ofile.write(f"hwid = {v}\n")
                            elif k == 'modelName':       ofile.write(f"modelname = {v}\n")
                            elif k == 'firmwareVersion': ofile.write(f"fwver = {v}\n")
            elif info.name == 'etc/config/network':
                with itar.extractfile(info) as fh:
                    for line in map(lambda x: x.decode().rstrip(), fh):
                        m = re.fullmatch(r"\t+option\s+(\w+)\s+'?([^']*)'?", line)
                        if m is not None:
                            k, v = m.group(1), m.group(2)
                            if k == 'macaddr':
                                ofile.write(f"macaddr = {v}\n")
                                break

    ofile.write("\n# Can edit from here.")
    ofile.flush()
    ofile.seek(0)

    if outfile:
        outfile.write(ofile.getvalue().encode()+b'\n')
    else:
        print(ofile.getvalue())

    return True

@commands.register
def jailbreak(*, session, base, url, dropbear=None, **kwargs):
    '''enable root login via ssh'''

    # download config
    vprint('downloading existing config')
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
                            vprint(f'patched {info.name} to fix root login vuln')
                    patch(info, data)
                elif info.name == 'etc/config/dropbear':
                    # enable dropbear
                    with itar.extractfile(info) as fh:
                        data, n = re.subn(rb"(option enable ')off", rb"\1on", fh.read())
                        if n or DRYRUN:
                            vprint(f'patched {info.name} to enable ssh')
                    patch(info, data)
                elif info.isfile():
                    # add regular file
                    otar.addfile(info, itar.extractfile(info))
                else:
                    # add special file
                    otar.addfile(info)

        if not dropbear:
            vprint(f'injecting dropbear binary from {DBTAR}:{DBBIN}')
            dbtar = tarfile.open(DBTAR)
            info = dbtar.getmember(DBBIN)
            otar.addfile(info, dbtar.extractfile(info))
        else:
            vprint(f'injecting dropbear binary from {dropbear}')
            otar.add(dropbear, 'usr/sbin/dropbear', None, filter=mutate)

    ofile.flush()
    ofile.seek(0)

    # upload config
    vprint('uploading modified config')
    return putconfig(session=session, base=base, url=url, infile=ofile, **kwargs)

if __name__ == '__main__':
    from urllib3.util import parse_url
    from argparse import ArgumentParser, ArgumentTypeError, HelpFormatter, FileType

    command_names = commands.keys()
    command_help = f'command to perform {{{", ".join(command_names)}}}'

    class Action:
        def __init__(self, metavar=None, help=None):
            self.metavar = metavar
            self.help = help

        def __getattr__(self, attr):
            if attr[0] == '_':
                msg = f"'{self.__class__.__name__}' object has no attribute '{attr}'"
                raise AttributeError(msg)

            return None

        def __repr__(self):
            params = f"(help={repr(self.help)}, metavar={repr(self.metavar)})"
            return self.__class__.__name__ + params

    class CustomFormatter(HelpFormatter):
        def _indented(self, text):
            return f'{" " * self._current_indent}{text}'

        def _format_action(self, action, *args, **kwargs):
            help_text = super()._format_action(action, *args, **kwargs)

            try:
                extra_text, extra_flag = '', False
                if action.dest == 'command':
                    self._dedent()
                    extra_text += self._indented('available commands:\n')
                    self._indent()

                    for command in command_names:
                        docstr = getdocstr(commands[command])
                        if docstr is not None:
                            extra_flag = True
                            act = Action(command, docstr)
                            extra_text += super()._format_action(act)

                return help_text + (f'\n{extra_text}\n' if extra_flag else '')
            except Exception as e:
                eprint(e)

            return help_text

    def URLType(a):
        return parse_url(a)

    parser = ArgumentParser(
        usage='%(prog)s COMMAND [options]',
        description='Manage EnGenius EnSky WiFi Access Points.',
        formatter_class=CustomFormatter,
    )

    parser.add_argument(
        'command', metavar='COMMAND', choices=command_names,
        help=command_help,
    )

    parser.add_argument(
        '-v', '--verbose', dest='verbose', action='store_true',
        help='enable verbose output',
    )

    parser.add_argument(
        '-n', '--dryrun', dest='dryrun', action='store_true',
        help='perform a trial run with no changes made',
    )

    parser.add_argument(
        '-u', '--username', dest='username', metavar='USER', default='admin',
        help='login username (default: "admin")',
    )
    parser.add_argument(
        '-p', '--password', dest='password', metavar='PASS', default=None,
        help='login password (default: `EAP_PASSWORD` environment variable if set, '+
             'otherwise "admin")',
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
        help='device IP address or URL',
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
    if args.password is None:
        args.password = os.environ.get('EAP_PASSWORD', 'admin')
    if args.verbose: VERBOSE = True
    if args.dryrun: DRYRUN = True

    # don't pass none values
    kwargs = dict(filter(lambda item: item[1] is not None, vars(args).items()))
    # extract command
    command = kwargs.pop('command')

    # fixups
    if 'wait' not in kwargs: kwargs['wait'] = False
    if 'url' in kwargs:
        url = f"{(kwargs['url'].scheme or 'http')}://{kwargs['url'].host}"
        kwargs['url'] = parse_url(url)
    else:
        kwargs['url'] = parse_url('http://192.168.0.1')

    # defaults
    if 'infile' not in kwargs and not stdout.isatty():
        kwargs['infile'] = os.fdopen(stdin.fileno(), "rb", closefd=False)

    if 'outfile' not in kwargs and not stdout.isatty():
        kwargs['outfile'] = os.fdopen(stdout.fileno(), "wb", closefd=False)

    # dispatch
    kwargs['session'], kwargs['base'] = login(**kwargs)
    commands.dispatch(command, **kwargs)
