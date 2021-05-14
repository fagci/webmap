#!/usr/bin/env python3

from collections import OrderedDict
from bs4 import BeautifulSoup
from fire import Fire
from requests.sessions import Session


class WebMap(Session):
    def __init__(self, target):
        super().__init__()
        self.target = target

        self.headers['User-Agent'] = 'Mozilla/5.0'
        self.interesting_headers = {'server', 'x-powered-by'}

        self.checks = OrderedDict(
            domains=self.check_domains,
            headers=self.check_headers,
            source=self.check_source,
        )

        self.prepare()

    def prepare(self):
        print('Prepare...')
        self.first_tresponse = self.get(self.target)

    def check(self, checks):
        for check_name, check in self.checks.items():
            if checks is None or check_name in checks:
                print('Checking', check_name)
                check()

    def check_domains(self):
        '''Get available domains from certificate'''
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


def main(target, checks=None):
    WebMap(target).check(checks)


if __name__ == '__main__':
    Fire(main)
