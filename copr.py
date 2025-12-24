""" WSGI-based  filtering reverse proxy for github push webhooks to COPR. """

import fnmatch
import json
import re
import traceback
from urllib.parse import parse_qs, unquote
from uuid import UUID
import hashlib
import hmac
from http.client import responses
import requests
from yaml import safe_load

class ProxyError(BaseException):
    """ A simple error class. """

    def __init__(self, code, reason=''):
        self.code = code
        self.reason = reason

    def __str__(self):
        """ Return standard code and statustext """
        return f'{self.code} {responses[self.code]}'

    def statustext(self):
        """ Return statustext """
        return responses[self.code]

class CoprProxy:
    """ A simple reverse proxy for COPR using WSGI. """

    def __init__(self, env, start_response):
        """ init our environment. """
        self.env = env
        self.start_response = start_response
        self.err = env['wsgi.errors']
        config = env.get('config')
        if config is None:
            raise ProxyError(503, 'config not specified')
        try:
            with open(config, 'r', encoding='utf-8') as f:
                self.cfg  = safe_load(f)
        except (ValueError, OSError) as ex:
            raise ProxyError(503, f'Unable to read config from {config}') from ex

    def debug(self):
        """ Return the configured debug flag """
        ret = self.cfg.get('debug')
        if ret is None:
            return False
        return ret

    def dryrun(self):
        """ Return the configured dryrun flag """
        ret = self.cfg.get('dryrun')
        if ret is None:
            return False
        return ret

    def strict(self):
        """ Return the configured strict flag """
        ret = self.cfg.get('strict')
        if ret is None:
            return True
        return ret

    def secret(self):
        """ Return the configured secret """
        ret = self.cfg.get('secret')
        if ret is None and self.strict():
            raise ProxyError(503, 'Strict validation enabled, but no secret configured locally')
        return ret

    def paths(self):
        """ Return the configured paths """
        ret = self.cfg.get('paths')
        if ret is None:
            return ret
        if isinstance(ret, str):
            return [ret]
        if isinstance(ret, (list, tuple)):
            return ret
        raise ProxyError(503, 'Invalid type of paths. Must be a str, a list or a tuple')

    def proxies(self):
        """ fetch proxies from environment. """
        ret = {}
        for scheme in ['http', 'https']:
            value = self.env.get(f'{scheme}_proxy')
            if value is not None:
                ret[scheme] = value
        return ret

    def checkuuid(self, uuid):
        """ Validate UUID. """
        if uuid is None:
            raise ProxyError(400, 'Missing uuid')
        try:
            tuuid = str(UUID(uuid)).lower()
        except ValueError as ex:
            raise ProxyError(400, 'Invalid UUID') from ex
        if tuuid != uuid.lower():
            raise ProxyError(400, 'Invalid UUID')

    def lmatch(self, pattern, slist):
        """ Invoke fnmatch on a list of strings.  """
        if slist is None:
            return False
        for s in slist:
            if fnmatch.fnmatch(s, pattern):
                return True
        return False

    def sigvalidate(self):
        """Verify that the payload was sent from GitHub by validating SHA256.

        Signature is provided by github in a Header like this:

        X-Hub-Signature-256: sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17

        Returns body, if secret is None or has vas validated successfully,

        See: https://docs.github.com/en/webhooks/webhook-events-and-payloads#delivery-headers
        """
        body = self.env['wsgi.input'].read(self.contentlen()).decode('utf-8')
        secret = self.secret()
        if secret is None:
            return body
        sig = self.env.get('HTTP_X_HUB_SIGNATURE_256')
        if sig is None:
            raise ProxyError(403, 'Signature missing')
        hobj = hmac.new(secret.encode('utf-8'), msg=body.encode('utf-8'), digestmod=hashlib.sha256)
        expected = 'sha256=' + hobj.hexdigest()
        if hmac.compare_digest(expected, sig):
            return body
        raise ProxyError(403, 'Signature validation failed')

    def contentlen(self):
        """ Get content length """
        clen = self.env.get('CONTENT_LENGTH', '0')
        if not re.match(r'[0-9]+$', clen):
            raise ProxyError(400, 'Invalid Content-Length')
        if int(clen) > 20971520:
            raise ProxyError(413, 'Invalid Content-Length')
        return int(clen)

    def urlparams(self):
        """ Handle URL parameters """
        try:
            qparams =  parse_qs(unquote(self.env['QUERY_STRING']), strict_parsing=True,
                                max_num_fields=3)
            proj = qparams.get('proj')
            if proj is None:
                raise ProxyError(400, 'Missing or empty proj')
            proj = proj[0]
            if not re.match('^[0-9]+$', proj):
                raise ProxyError(400, 'Invalid proj')
            uuid = qparams.get('uuid')
            if uuid is not None:
                uuid = uuid[0]
            self.checkuuid(uuid)
            pkg = qparams.get('pkg')
            if pkg is not None:
                pkg = pkg[0]
        except ValueError as ex:
            raise ProxyError(400, 'Too many query parameters') from ex

        return {'proj': proj, 'uuid': uuid, 'pkg': pkg}

    def pathmatch(self, obj):
        """ Handle path matching """
        paths = self.paths()
        if paths is None:
            return True
        if 'commits' in obj:
            candidates = []
            for c in obj['commits']:
                candidates += c['added'] + c['modified'] + c['removed']
            for pat in paths:
                if self.lmatch(pat, candidates):
                    return True
        else:
            raise ProxyError(400, 'missing commits')
        return False

    def forward(self, dst, ua, ctype, body):
        """ Forward request to destination. """
        hdrs = {}
        hdrs['User-Agent'] = ua
        hdrs['Content-Type'] = ctype
        hdrs['Content-Length'] = self.env['CONTENT_LENGTH']
        for key in self.env.keys():
            m = re.search(r'^HTTP_X_GITHUB_(\S+)', key)
            if m is not None and m.group(1):
                hk = '-'.join(word.capitalize() for word in m.group(1).split('_'))
                hdrs[f'X-Github-{hk}'] = self.env[key]
            m = re.search(r'^HTTP_X_HUB_(\S+)', key)
            if m is not None and m.group(1):
                hk = '-'.join(word.capitalize() for word in m.group(1).split('_'))
                hdrs[f'X-Hub-{hk}'] = self.env[key]
        try:
            return requests.post(dst, headers=hdrs, data=body, proxies=self.proxies(),
                              timeout=10)
        except requests.Timeout as ex:
            raise ProxyError(504, ex.args[0]) from ex
        except (requests.RequestException, requests.TooManyRedirects,
                requests.JSONDecodeError) as ex:
            raise ProxyError(500, ex.args[0]) from ex

    def formatdst(self, projectid, uuid, pkgname):
        """ Format destination URL. """
        try:
            if pkgname is None:
                fmt = self.cfg.get('copr_url_2')
                if fmt is None:
                    raise ProxyError(503, 'Missing URL template copr_url_nopkg')
                return fmt.format(projectid=projectid, uuid=uuid)
            fmt = self.cfg.get('copr_url_3')
            if fmt is None:
                raise ProxyError(503, 'Missing URL template copr_url_pkg')
            return fmt.format(projectid=projectid, uuid=uuid, pkgname=pkgname)
        except KeyError as ex:
            raise ProxyError(503, f'Misconfigured url template. Missing key: {ex}') from ex

    def handle(self):
        """ Handle one request. """

        ua = self.env.get('HTTP_USER_AGENT')
        ctype = self.env.get('CONTENT_TYPE')
        ghe  = self.env.get('HTTP_X_GITHUB_EVENT')

        # Basic sanity checks
        if ua is None or not re.match(r'GitHub-Hookshot/.+', ua):
            raise ProxyError(403, 'User-Agent does not match GitHub-Hookshot/')
        if ctype is None or not ctype == 'application/json':
            raise ProxyError(403, 'Invalid Content-Type')
        if ghe is None:
            raise ProxyError(403, 'Missing X-GitHub-Event')

        if self.env['REQUEST_METHOD'] == 'POST':

            body = self.sigvalidate()
            if ghe != 'push':
                raise ProxyError(400, 'Not a push event')

            q = self.urlparams()
            try:
                obj = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as ex:
                raise ProxyError(400, 'Invalid JSON') from ex

            if self.pathmatch(obj):
                dst = self.formatdst(q['proj'], q['uuid'], q['pkg'])
                if self.dryrun():
                    print(f'Found pattern in commit, would forward to {dst}', file=self.err)
                else:
                    print(f'Found pattern in commit, forwarding to {dst}', file=self.err)
                    r = self.forward(dst, ua, ctype, body)
                    self.start_response(f'{r.status_code} {r.reason}', [])
                    return [r.content]

        self.start_response('200 OK', [])
        return []

def application(env, start_response):
    """ WSGI entrypoint. """
    try:
        rp = CoprProxy(env, start_response)
        return rp.handle()
    except ProxyError as ex:
        print(f'{ex.code}: {ex.reason}', file=env['wsgi.errors'])
        if rp.debug():
            traceback.print_exception(ex, file=env['wsgi.errors'])
        start_response(str(ex), [('Content-Type', 'text/plain; charset=utf-8')])
        if ex.code in [403, 503]:
            # For security reasons, do not expose the cause.
            return []
        # For other errors, expose the cause.
        return [str(ex.reason).encode('utf-8')]
