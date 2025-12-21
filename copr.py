""" WSGI-based  filtering reverse proxy for github push webhooks to COPR. """

import fnmatch
import json
import re
from urllib.parse import parse_qs
from urllib.request import getproxies
from uuid import UUID
import requests

COPR_URL = 'https://copr.fedorainfracloud.org/webhooks/github/{0}/{1}/{2}/'

def forbidden(msg, start_response):
    """ Generate a 403 error. Log msg to log only. """
    print(f'403: {msg}', file=globals()['err'])
    start_response('403 Forbidden', [])
    return []

def bad(msg, start_response):
    """ Generate a 400 error. """
    print(f'400: {msg}', file=globals()['err'])
    start_response('400 Bad Request', [])
    return [msg.encode('utf-8')]

def uuid_valid(val):
    """ Validate UUID. """
    try:
        return str(UUID(str(val))) == str(val)
    except ValueError:
        return False

def lmatch(pattern, slist):
    """ Invoke fnmatch on a list of strings.  """
    if slist is None:
        return False
    for s in slist:
        if fnmatch.fnmatch(s, pattern):
            return True
    return False

def application(env, start_response):
    """ WSGI entrypoint. """
    err = env['wsgi.errors']
    globals()['err'] = err
    meth = env['REQUEST_METHOD']
    ua = env.get('HTTP_USER_AGENT')
    ctype = env.get('CONTENT_TYPE')
    clen = env.get('CONTENT_LENGTH', '0')
    ghe  = env.get('X_GITHUB_EVENT', '')

    # Basic sanity checks
    if ua is None or not re.match(r'GitHub-Hookshot/.+', ua):
        return forbidden('User-Agent does not match GitHub-Hookshot/', start_response)
    if ctype is None or not ctype == 'application/json':
        return forbidden('Invalid Content-Type', start_response)
    if clen is None or not re.match(r'[0-9]+$', clen):
        return forbidden('Invalid Content-Length', start_response)
    if ghe == '':
        return forbidden('Missing X-GitHub-Event', start_response)

    keys = env.keys()
    if meth == 'POST':

        if ghe != 'push':
            return bad('Not a push event', start_response)

        try:
            qparams =  parse_qs(env['QUERY_STRING'], strict_parsing=True, max_num_fields=4)
            proj = qparams.get('proj', '')
            if proj == '':
                return bad('Missing or empty proj', start_response)
            if not re.match('^[0-9]+$', proj):
                return bad('Invalid proj', start_response)
            uuid = qparams.get('uuid', '')
            if not uuid_valid(uuid):
                return bad('Invalid uuid', start_response)
            pkg = qparams.get('pkg', '')
            pat = qparams.get('pat', '')
        except ValueError:
            return bad('Too many query parameters', start_response)

        body = env['wsgi.input'].read(int(clen)).decode('utf-8')
        try:
            obj = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return bad('Invalid json', start_response)


        pat = 'syncstorage-rs.spec'

        found = False
        if 'commits' in obj:
            if pat == '':
                found = True
            else:
                for c in obj['commits']:
                    if lmatch(pat, c['added']) or lmatch(pat, c['modified']):
                        found = True
        else:
            return bad('missing commits', start_response)

        if found:
            dst = COPR_URL.format(proj, uuid, pkg)
            if pkg == '':
                dst = dst[:-1]
            print(f'Found {pat} in request, forwarding to {dst}', file=err)
            hdrs = {}
            hdrs['User-Agent'] = ua
            hdrs['Content-Type'] = ctype
            hdrs['Content-Length'] = clen
            for key in keys:
                m = re.search(r'^HTTP_X_GITHUB_(\S+)', key)
                if m is not None and m.group(1):
                    hk = '-'.join(word.capitalize() for word in m.group(1).split('_'))
                    hdrs[f'X-Github-{hk}'] = env[key]
            try:
                r = requests.post(dst, headers=hdrs, data=body, proxies=getproxies(), timeout=10)
            except requests.Timeout as ex:
                print(ex.args[0], file=err)
                start_response('504 Gateway Timeout', [])
                return []
            except (requests.RequestException, requests.TooManyRedirects,
                    requests.JSONDecodeError) as ex:
                print(ex.args[0], file=err)
                start_response('500 Internal server Error', [])
                return []

            start_response(f'{r.status_code} {r.reason}', [])
            return [r.content]

    start_response('200 KO', [])
    return []
