#!/usr/bin/env python3

from collections import OrderedDict
from pathlib import Path
from socket import gethostbyname
from urllib.parse import urlparse

from fire import Fire
from requests.exceptions import SSLError
from requests.sessions import Session
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from lib.colors import CEND, CEND, CGREY, CGREY, CDGREY, CEND, found, nfound, info, err
from lib.parse import get_analytics, get_social, get_contacts, get_linked_domains
from lib.utils import get_domains_from_cert, reverse_dns

disable_warnings(InsecureRequestWarning)

BANNER = r"""
%s__      _____| |__  _ __ ___   __ _ _ __
%s\ \ /\ / / _ \ '_ \| '_ ` _ \ / _` | '_ \
%s \ V  V /  __/ |_) | | | | | | (_| | |_) |
%s  \_/\_/ \___|_.__/|_| |_| |_|\__,_| .__/
%s by fagci                          |_|%s""" % (
    CEND,
    CEND,
    CGREY,
    CGREY,
    CDGREY,
    CEND
)


class WebMap(Session):
    techs = []
    cmses = []
    DIR = Path(__file__).resolve().parent

    __slots__ = ('target', 'fuzz', 'subdomains', 'allow_redirects', 'scheme',
                 'hostname', 'netloc', 'port', 'path', 'ip', 'response', 'html', 'interesting_headers')

    def __init__(self, target, fuzz=False, subdomains=False, allow_redirects=False, resolve_ip=True):
        super().__init__()
        self.headers['User-Agent'] = 'Mozilla/5.0'

        # initial data
        self.target = target
        self.fuzz = fuzz
        self.subdomains = subdomains
        self.allow_redirects = allow_redirects

        # all defined checks
        self.checks = OrderedDict(
            # base info
            headers=self.check_headers,
            domains=self.check_domains,
            # parse source
            linked_domains=self.check_linked_domains,
            robots_disallow=self.check_robots,
            cms=self.check_cms,
            techs=self.check_techs,
            analytics=self.check_analytics,
            contacts=self.check_contacts,
            social=self.check_social,
            # fuzz
            fuzz=self.check_fuzz,
            subdomains=self.check_subdomains,
        )

        self.interesting_headers = {
            'access-control-allow-origin',
            'content-security-policy',  # for additional domains. Deprecated?
            'last-modified',
            'server',
            'set-cookie',
            'via',
            'x-backend-server',
            'x-powered-by',
        }

        # target url parts
        pu = urlparse(target)
        self.scheme = pu.scheme
        self.hostname = pu.hostname
        self.netloc = pu.netloc
        self.port = pu.port or {'http': 80, 'https': 443}.get(self.scheme)
        self.path = pu.path

        if resolve_ip and self.hostname:
            self.ip = gethostbyname(self.hostname)

        info(f'Target: {self.target}')
        info('IP:', self.ip or 'not resolved')
        print('-'*42)

        self.prepare()

    def prepare(self):
        '''Make initial request'''
        info('Get initial response...')

        try:
            self.response = self.get(
                self.target, allow_redirects=self.allow_redirects)
        except SSLError as e:
            err('SSL error', e)
            self.response = self.get(
                self.target, allow_redirects=self.allow_redirects, verify=False)

        if not self.response.ok:
            raise Exception(f'Status: {self.response.status_code}')

        info(f'[{self.response.status_code}]')
        if self.response.is_redirect:
            info('Location:', self.response.headers.get('location'))
        self.html = self.response.text

    def check(self, checks=None):
        '''Run checks, or provided in param'''
        for check_name, check in self.checks.items():
            if check and (checks is None or check_name in checks):
                if check_name == 'fuzz' and not (self.fuzz or checks):
                    continue
                if (
                    check_name == 'subdomains'
                    and not self.subdomains
                    and not checks
                ):
                    continue
                print(f'\n{check_name.upper()}')
                res = check()
                if not res:
                    nfound('no data')
                    continue

                if isinstance(res, dict):
                    for n, r in res.items():
                        if isinstance(r, str):
                            found(f'{n}:', r)
                        else:
                            found(f'{n}:', ', '.join(r))
                elif isinstance(res, list):
                    found(', '.join(res))
                elif isinstance(res, set):
                    for r in res:
                        found(r)
                elif not isinstance(res, bool):
                    found(res)
                else:
                    info('found')

    def check_domains(self):
        '''Get available domains'''
        res = {}
        if self.scheme == 'https':
            domains = get_domains_from_cert(self.hostname, self.port or 443)
            if domains:
                res['cert'] = domains
        domain = reverse_dns(self.ip)
        if domain:
            res['rDNS'] = [domain]
        return res

    def check_techs(self):
        '''Get used techs'''
        if not WebMap.techs:
            with (self.DIR / 'data/tech.txt').open() as f:
                WebMap.techs = f.read().splitlines()
        res = filter(lambda x: x in self.html, self.techs)
        return list(res)

    def check_cms(self):
        '''Get used CMS from HTML'''
        if not WebMap.cmses:
            with (self.DIR / 'data/cms.txt').open() as f:
                WebMap.cmses = f.read().splitlines()
        res = filter(lambda x: x in self.html, self.cmses)
        return list(res)

    def check_fuzz(self):
        '''Fuzz paths to find misconfigs'''
        from concurrent.futures import ThreadPoolExecutor
        from random import randrange
        from lib.progress import Progress
        # First, try to check if random path exists.
        # If it is, we potentially cant find misconfigs,
        # coz it is SPA
        random_path = ''.join(chr(randrange(ord('a'), ord('z')+1))
                              for _ in range(8))
        ok, path, *_ = self._check_path(f'/{random_path}')
        if ok:
            info(path, 'possible SPA')
            return False
        paths = (
            self.DIR / 'data/fuzz_common.txt',
        )
        status = False
        for p in paths:
            with p.open() as f:
                progress = Progress(sum(1 for _ in f))
                f.seek(0)
                with ThreadPoolExecutor() as ex:
                    r = ex.map(self._check_path, f.read().splitlines())
                    for res, path, code, c_len in r:
                        if res:
                            print(end='\r')
                            found(f'[{code}] {path} ({c_len} B)')
                            status = True
                        progress(path)
        return status

    def check_subdomains(self):
        '''Fuzz paths to find misconfigs'''
        from concurrent.futures import ThreadPoolExecutor
        from lib.progress import Progress
        paths = (
            self.DIR / 'data/fuzz_subdomain.txt',
        )
        status = False
        for p in paths:
            with p.open() as f:
                progress = Progress(sum(1 for _ in f))
                f.seek(0)
                with ThreadPoolExecutor() as ex:
                    r = ex.map(self._check_subdomain, f.read().splitlines())
                    for _, sd, code, c_len in r:
                        if code // 100 == 2:
                            print(end='\r')
                            found(f'[{code}] {sd} ({c_len} B)')
                            status = True
                        progress(sd)
        return status

    def check_linked_domains(self):
        '''Get linked domains from HTML'''
        return get_linked_domains(self.html, self.hostname)

    def check_headers(self):
        '''Get interesting headers'''
        return {k: v for k, v in self.response.headers.lower_items() if k in self.interesting_headers}

    def check_analytics(self):
        '''Get analytics IDs'''
        return get_analytics(self.html)

    def check_social(self):
        '''Get social links'''
        return get_social(self.html)

    def check_contacts(self):
        '''Get contact information'''
        return get_contacts(self.html)

    def check_robots(self):
        response = self.get(
            f'{self.scheme}://{self.netloc}/robots.txt', verify=False, allow_redirects=False)
        if response.status_code // 100 == 2:
            return {l.split(None, 1)[1] for l in response.text.splitlines() if l.startswith('Disallow: ')}

    def _check_path(self, path) -> tuple[bool, str, int, int]:
        '''Check path for statuses < 400 without verification'''
        # NOTE: all paths fuzzed from target root
        url = f'{self.target}{path}'
        response = self.get(url, verify=False, timeout=5,
                            stream=True, allow_redirects=False)
        return response.status_code//100 == 2, path, response.status_code, len(response.content)

    def _check_subdomain(self, subdomain) -> tuple[bool, str, int, int]:
        '''Check path for statuses < 400 without verification'''
        try:
            url = f'{self.scheme}://{subdomain}.{self.netloc}'
            response = self.get(url, verify=False, timeout=5,
                                stream=True, allow_redirects=False)
            return response.status_code//100 == 2, subdomain, response.status_code, len(response.content)
        except:
            return False, subdomain, 999, 0


def main(target, checks=None, n=False, fuzz=False, subdomains=False, r=False, full=False):
    print('='*42)
    print(BANNER.strip())
    print('='*42)
    if full:
        fuzz = True
        subdomains = True
        checks = None  # all
    WebMap(target, resolve_ip=not n, fuzz=fuzz,
           subdomains=subdomains,
           allow_redirects=r).check(checks)


if __name__ == '__main__':
    try:
        Fire(main)
    except KeyboardInterrupt:
        exit(130)
    except Exception as e:
        err(repr(e))
