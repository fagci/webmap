#!/usr/bin/env python3

from collections import OrderedDict, defaultdict
from pathlib import Path
from socket import gethostbyname
from urllib.parse import urlparse

from bs4 import BeautifulSoup
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

    def __init__(self, target, resolve_ip=True, fuzz=False, allow_redirects=False):
        super().__init__()
        self.target = target
        self.fuzz = fuzz
        self.allow_redirects = allow_redirects
        pu = urlparse(target)
        self.scheme = pu.scheme
        self.hostname = pu.hostname
        self.netloc = pu.netloc
        self.port = pu.port
        self.path = pu.path

        if not self.port:
            self.port = {'http': 80, 'https': 443}.get(self.scheme)

        info(f'Target: {self.target}')

        if self.hostname and resolve_ip:
            self.ip = gethostbyname(self.hostname)
            info('IP:', self.ip)

        self.headers['User-Agent'] = 'Mozilla/5.0'
        self.interesting_headers = {
            'access-control-allow-origin',
            'last-modified',
            'server',
            'set-cookie',
            'via',
            'x-backend-server',
            'x-powered-by',
        }

        self.checks = OrderedDict(
            domains=self.check_domains,
            linked_domains=self.check_linked_domains,
            headers=self.check_headers,
            techs=self.check_techs,
            cms=self.check_cms,
            analytics=self.check_analytics,
            social=self.check_social,
            contacts=self.check_contacts,
            fuzz=self.check_fuzz,
        )

        print('-'*42)
        self.prepare()

    def prepare(self):
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

    def check(self, checks):
        for check_name, check in self.checks.items():
            if check and (checks is None or check_name in checks):
                if check_name == 'fuzz' and not (self.fuzz or checks):
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
                elif isinstance(res, list) or isinstance(res, set):
                    found(*res)
                elif not isinstance(res, bool):
                    found(res)
                else:
                    found('found')

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
        if not WebMap.techs:
            with (self.DIR / 'data/tech.txt').open() as f:
                WebMap.techs = f.read().splitlines()
        res = filter(lambda x: x in self.response.text, self.techs)
        return list(res)

    def check_cms(self):
        if not WebMap.cmses:
            with (self.DIR / 'data/cms.txt').open() as f:
                WebMap.cmses = f.read().splitlines()
        res = filter(lambda x: x in self.response.text, self.cmses)
        return list(res)

    def check_linked_domains(self):
        return get_linked_domains(self.response.text, self.hostname)

    def check_fuzz(self):
        from concurrent.futures import ThreadPoolExecutor
        from lib.progress import Progress
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

    def check_headers(self):
        '''Get interesting headers'''
        return {k: v for k, v in self.response.headers.lower_items() if k in self.interesting_headers}

    def check_analytics(self):
        '''Get analytics IDs'''
        return get_analytics(self.response.text)

    def check_social(self):
        '''Get social links'''
        return get_social(self.response.text)

    def check_contacts(self):
        '''Get contact information'''
        return get_contacts(self.response.text)

    def _check_path(self, path) -> tuple[bool, str, int, int]:
        url = f'{self.target}{path}'
        response = self.get(url, verify=False, timeout=5, stream=True)
        return response.ok, path, response.status_code, len(response.content)

    def _get_page(self, url):
        response = self.get(url, allow_redirects=False)
        return BeautifulSoup(response.text, 'lxml')


def main(target, checks=None, n=False, fuzz=False, r=False):
    print('='*42)
    print(BANNER.strip())
    print('='*42)
    WebMap(target, resolve_ip=not n, fuzz=fuzz,
           allow_redirects=r).check(checks)


if __name__ == '__main__':
    try:
        Fire(main)
    except KeyboardInterrupt:
        exit(130)
    except Exception as e:
        err(repr(e))
