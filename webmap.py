#!/usr/bin/env python3

from collections import OrderedDict
from socket import gethostbyname
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fire import Fire
from requests.exceptions import SSLError
from requests.sessions import Session
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from lib import get_domains_from_cert, reverse_dns

disable_warnings(InsecureRequestWarning)


class WebMap(Session):
    def __init__(self, target, resolve_ip=True):
        super().__init__()
        self.target = target
        pu = urlparse(target)
        self.scheme = pu.scheme
        self.hostname = pu.hostname
        self.netloc = pu.netloc
        self.port = pu.port
        self.path = pu.path

        if not self.port:
            self.port = {'http': 80, 'https': 443}.get(self.scheme)

        print(f'''
                Hostname: {self.hostname}
                Netloc: {self.netloc}
                Port: {self.port}
                Path: {self.path}
                ''')

        if self.hostname and resolve_ip:
            self.ip = gethostbyname(self.hostname)

        self.headers['User-Agent'] = 'Mozilla/5.0'
        self.interesting_headers = {'server', 'x-powered-by'}

        self.checks = OrderedDict(
            domains=self.check_domains,
            headers=self.check_headers,
            source=self.check_source,
        )

        self.prepare()

    def prepare(self):
        print('[*] Prepare...')

        try:
            self.first_tresponse = self.get(self.target, allow_redirects=False)
        except SSLError as e:
            print('[E] SSL error', e)
            self.first_tresponse = self.get(
                self.target, allow_redirects=False, verify=False)

    def check(self, checks):
        for check_name, check in self.checks.items():
            if checks is None or check_name in checks:
                print('[*] Checking', check_name)
                check()

    def check_domains(self):
        '''Get available domains'''
        domains_from_cert = get_domains_from_cert(self.hostname, self.port)
        domain_from_rdns = reverse_dns(self.ip)
        print(*(domains_from_cert+[domain_from_rdns]))
        pass

    def check_source(self):
        pass

    def check_headers(self):
        '''Get interesting headers'''
        for k, v in self.first_tresponse.headers.items():
            if k in self.interesting_headers:
                print(f'{k}: {v}')

    def check_url(self, url):
        return self.get(url).status_code == 200

    def get_page(self, response):
        return BeautifulSoup(response.text, 'lxml')


def main(target, checks=None, n=False):
    WebMap(target, resolve_ip=not n).check(checks)


if __name__ == '__main__':
    try:
        Fire(main)
    except KeyboardInterrupt:
        exit(130)
    except Exception as e:
        print('[E]', repr(e))
