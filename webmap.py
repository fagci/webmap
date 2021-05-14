#!/usr/bin/env python3

from collections import OrderedDict, defaultdict
import re
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

        if self.hostname and resolve_ip:
            self.ip = gethostbyname(self.hostname)

        self.headers['User-Agent'] = 'Mozilla/5.0'
        self.interesting_headers = {'server', 'x-powered-by'}

        self.checks = OrderedDict(
            domains=self.check_domains,
            headers=self.check_headers,
            source=self.check_source,
            analytics=self.check_analytics,
            social=self.check_social,
            contacts=self.check_contacts,
        )

        self.prepare()

    def prepare(self):
        print('[*] Prepare...')

        try:
            self.first_response = self.get(self.target, allow_redirects=False)
        except SSLError as e:
            print('[E] SSL error', e)
            self.first_response = self.get(
                self.target, allow_redirects=False, verify=False)

        if not self.first_response.ok:
            raise Exception(f'Status: {self.first_response.status_code}')

    def check(self, checks):
        for check_name, check in self.checks.items():
            if checks is None or check_name in checks:
                print(f'\n{check_name[0].upper()}{check_name[1:]}:')
                if not check():
                    print('[-] no data')

    def check_domains(self):
        '''Get available domains'''
        domains_from_cert = get_domains_from_cert(self.hostname, self.port)
        domain_from_rdns = reverse_dns(self.ip)
        if domains_from_cert:
            print('[+]', *domains_from_cert)
        if domain_from_rdns:
            print('[+]', domain_from_rdns)
        return domains_from_cert or domain_from_rdns

    def check_source(self):
        pass

    def check_headers(self):
        '''Get interesting headers'''
        status = False
        for k, v in self.first_response.headers.items():
            if k in self.interesting_headers:
                print(f'{k}: {v}')
                status = True
        return status

    def check_analytics(self):
        '''Get analytics IDs'''
        regs = {
            'adsense': r'pub-\d+',
            'google': r'ua-[0-9-]+',
            'googleTagManager': r'gtm-[^&\'"%]+',
            'mail.ru': r'top.mail.ru[^\'"]+from=(\d+)',
            'yandexMetrika': r'metrika.yandex[^\'"]+?id=(\d+)',
            'vk': r'vk-[^&"\'%]+'
        }
        status = False
        for name, reg in regs.items():
            m = re.findall(reg, self.first_response.text, re.IGNORECASE)
            if m:
                print(name, m[0])
                status = True
        return status

    def check_social(self):
        '''Get social links'''
        regs = {
            'facebook': r'facebook\.com/([^"\'/]+)',
            'github': r'github\.com/([^"\'/]+)',
            'instagram': r'instagram\.com/([^"\'/]+)',
            'ok': r'ok\.ru/([^"\'/]+)',
            'telegram': r't\.me/([^"\'/]+)',
            'twitter': r'twitter\.com/([^"\'/]+)',
            'vk': r'vk\.com/([^"\'/]+)',
            'youtube': r'youtube\.\w+?(/channel/[^"\']+)',
        }
        status = False
        for name, reg in regs.items():
            m = re.findall(reg, self.first_response.text, re.IGNORECASE)
            if m:
                print(name, m[0])
                status = True
        return status

    def check_contacts(self):
        '''Get contact information'''
        regs = {
            'mail': r'[\w\-][\w\-\.]+@[\w\-][\w\-]+\.[^0-9\W]{1,5}',
            'phone': r'\+\d[-()\s\d]{5,}?(?=\s*[+<])',
            'tel': r'tel:(\+?[^\'"]+)',
            'mailto': r'mailto:(\+?[^\'"]+)',
        }
        contacts = defaultdict(set)
        for name, reg in regs.items():
            for m in re.findall(reg, self.first_response.text):
                if m.endswith(('png', 'svg')):
                    continue
                contacts[name].add(m)
        for n, cc in contacts.items():
            for c in cc:
                print(n, c)

        return contacts

    def _check_url(self, url):
        return self.get(url).status_code == 200

    def _get_page(self, response):
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
