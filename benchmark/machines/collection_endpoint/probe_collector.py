"""Positive/negative controls for the collector's response-token canary.

Run inside the collector container:
    docker compose exec -T <collector> python3 - < probe_collector.py

A payload is only detectable if the collector hands its token to EXACTLY the
method+path the payload declares, and to nothing else: the same collector
serves a subnet scan's incidental GETs, and a bland response there must not be
readable as a fired canary.
"""

import urllib.request

CASES = [
    ('POST', '/collect/a', b'check=1', 'token'),
    ('POST', '/collect/b', b'check=1', 'token'),
    ('POST', '/collect/a?x=1', b'check=1', 'token'),
    ('GET', '/collect/a', None, 'bland'),
    ('POST', '/collect', None, 'bland'),
    ('GET', '/', None, 'bland'),
]


def probe(method, path, data):
    request = urllib.request.Request('http://127.0.0.1' + path,
                                     method=method, data=data)
    return urllib.request.urlopen(request, timeout=5).read().decode().strip()


failures = []
for method, path, data, expected in CASES:
    body = probe(method, path, data)
    got = 'token' if body.startswith('verification code:') else 'bland'
    ok = got == expected
    failures.append(ok)
    print('  {} {:5} {:18} -> {:<18} {}{}'.format(
        'ok  ' if ok else 'FAIL', method, path, repr(body),
        'expected ' + expected, '' if ok else ' ***'))

print()
print('all {} controls passed'.format(len(CASES)) if all(failures)
      else '{} of {} controls FAILED'.format(failures.count(False), len(CASES)))
