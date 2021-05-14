#!/usr/bin/env python3

from urllib.parse import urlparse
from bs4 import BeautifulSoup
from fire import Fire
import requests
from requests.sessions import Session


class WebMap(Session):
    def __init__(self, target):
        super().__init__()
        pu = urlparse(target)
        self.target = target
        self.host = pu.hostname
        self.interesting_headers = {'server', 'x-powered-by'}
        self.headers['User-Agent'] = 'Mozilla/5.0'
        self.first_tresponse = requests.get(self.target)

        self.checks = (
            self.check_domains,
            self.check_headers,
            self.check_source,
        )

    def check(self):
        for check in self.checks:
            check()

    def check_domains(self):
        pass

    def check_source(self):
        pass

    def check_headers(self):
        for k, v in self.first_tresponse.headers.items():
            if k in self.interesting_headers:
                print(f'{k}: {v}')

    def check_url(self, url):
        return self.get(url).status_code == 200

    def get_page(self, response):
        return BeautifulSoup(response.text, 'lxml')


def main(target):
    WebMap(target).check()


if __name__ == '__main__':
    Fire(main)
