#!/usr/bin/env python3
"""
phpcheck.py — Python 3 port of OpenAI's php2shell-checker (phpcheck.js).

Checks a website URL or a local PHP binary and reports whether the PHP
version is vulnerable to php2shell (CVE-2026-109618 / CVE-2026-109619).

Exit codes: 0 OK, 1 VULNERABLE, 3 UNKNOWN, 2 usage error.
Faithful port of the Node.js logic; original (c) OpenAI, Apache-2.0.
"""

import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = '1.0.0'

# Vulnerable version cutoffs as of 2026-10-20. A newer stable patch in a
# listed branch is OK by this table; unlisted branches remain unknown.
VULNERABLE_THROUGH = {
    '5.4': 45, '5.5': 38, '5.6': 40,
    '7.0': 33, '7.1': 33, '7.2': 34, '7.3': 33, '7.4': 33,
    '8.0': 30, '8.1': 34, '8.2': 34, '8.3': 35, '8.4': 26, '8.5': 11,
}

USAGE = (
    'Usage: python3 phpcheck.py URL [--timeout SECONDS] [--json]\n'
    '       python3 phpcheck.py --local [--php PATH] [--json]\n'
    '       python3 phpcheck.py --version'
)

EXIT = {'ok': 0, 'vulnerable': 1, 'unknown': 3}

_VERSION_RE = re.compile(r'^(\d+)\.(\d+)\.(\d+)([-+~].*)?$')
_DEV_SUFFIX = re.compile(r'(?:^|[-+~.])(?:dev|alpha|beta|rc)', re.IGNORECASE)


def patch_status(version):
    """Return 'ok', 'vulnerable' or 'unknown' for a PHP version string."""
    m = _VERSION_RE.match(version or '')
    if not m:
        return 'unknown'
    cutoff = VULNERABLE_THROUGH.get(f'{int(m.group(1))}.{int(m.group(2))}')
    if cutoff is None:
        return 'unknown'
    if int(m.group(3)) <= cutoff:
        return 'vulnerable'
    # A development build of the next patch is not evidence of a stable fix.
    if m.group(4) and _DEV_SUFFIX.search(m.group(4)):
        return 'unknown'
    return 'ok'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response as-is instead of following it (Node: manual)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def url_headers(address, timeout):
    """HEAD the URL (GET on 405/501) and return 'Server\\nX-Powered-By'."""
    if re.search(r'[\x00-\x20\x7f]', address):
        raise ValueError('URL contains spaces or control characters')
    parts = urllib.parse.urlsplit(address)
    if parts.scheme not in ('http', 'https'):
        raise ValueError('Use an http:// or https:// URL')
    if parts.username or parts.password or parts.fragment:
        raise ValueError('URL credentials and fragments are not supported')

    opener = urllib.request.build_opener(_NoRedirect())
    headers = []
    for method in ('HEAD', 'GET'):
        req = urllib.request.Request(address, method=method)
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            # urllib raises HTTPError for status >= 400; headers are still there.
            resp = exc
        headers.append(resp.headers.get('Server') or '')
        headers.append(resp.headers.get('X-Powered-By') or '')
        resp.close()
        if resp.code not in (405, 501):
            break
    return '\n'.join(headers)


def _usage_error(message):
    print(message + '\n' + USAGE, file=sys.stderr)
    return 2


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv

    opts = {
        'local': False,
        'php': 'php',
        'timeout': '10',
        'json': False,
        'version': False,
        'help': False,
    }
    positionals = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-h', '--help'):
            opts['help'] = True
        elif arg == '--local':
            opts['local'] = True
        elif arg == '--json':
            opts['json'] = True
        elif arg == '--version':
            opts['version'] = True
        elif arg in ('--php', '--timeout'):
            i += 1
            if i >= len(args):
                return _usage_error(f'{arg} requires a value')
            opts[arg[2:]] = args[i]
        elif arg.startswith('--php=') or arg.startswith('--timeout='):
            key, _, value = arg.partition('=')
            opts[key[2:]] = value
        elif arg.startswith('-') and arg != '-':
            return _usage_error(f"Unknown option '{arg}'")
        else:
            positionals.append(arg)
        i += 1

    if opts['version']:
        print(VERSION)
        return 0
    if opts['help']:
        print(USAGE)
        return 0

    address = positionals[0] if positionals else None
    if len(positionals) > 1 or (opts['local'] and address is not None) \
            or (not opts['local'] and address is None):
        return _usage_error('Provide a URL or --local, not both')

    try:
        timeout = float(opts['timeout'])
    except ValueError:
        timeout = float('nan')
    if not opts['local'] and not (0 < timeout <= 60):
        return _usage_error('--timeout must be greater than 0 and at most 60 seconds')

    version = None
    error = None
    status = 'unknown'
    try:
        if opts['local']:
            text = subprocess.run(
                [opts['php'], '-v'],
                capture_output=True, text=True, timeout=10, check=True,
            ).stdout
            # Local output includes copyright text and may include startup warnings.
            pattern = re.compile(r'^PHP (\d[^\s,;)]*)', re.MULTILINE)
        else:
            text = url_headers(address, timeout)
            pattern = re.compile(r'\bPHP[ /]([^\s,;)]+)', re.IGNORECASE)

        for match in pattern.finditer(text):
            candidate = patch_status(match.group(1))
            # Do not let an OK banner hide a vulnerable or unrecognized PHP version.
            if version is None or candidate == 'vulnerable' or status == 'ok':
                version = match.group(1)
                status = candidate
            if status == 'vulnerable':
                break
    except Exception as exc:
        error = str(exc)

    code = EXIT[status]
    reason = error or (f'PHP {version}' if version else 'PHP version not found')
    report = {
        'patch_status': status,
        'php_version': version,
        'reason': reason,
        'exit_code': code,
    }
    if opts['json']:
        print(json.dumps(report))
    else:
        print(f'{status.upper()}: {reason}')
    return code


if __name__ == '__main__':
    sys.exit(main())
