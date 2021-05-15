from html.parser import HTMLParser
import re
from collections import defaultdict


def get_analytics(html):
    result = defaultdict(set)
    regs = {
        'adsense': r'pub-\d+',
        'google': r'ua-[0-9-]+',
        'googleTagManager': r'gtm-[^&\'"%]+',
        'mail.ru': r'top.mail.ru[^\'"]+from=(\d+)',
        'yandexMetrika': r'metrika.yandex[^\'"]+?id=(\d+)',
        'vk': r'vk-[^&"\'%]+'
    }
    for name, reg in regs.items():
        m = re.findall(reg, html, re.IGNORECASE)
        if m:
            result[name].add(m[0])
    return result


def get_social(html):
    result = defaultdict(set)
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
    for name, reg in regs.items():
        m = re.findall(reg, html, re.IGNORECASE)
        if m:
            result[name].add(m[0])
    return result


def get_contacts(html):
    from html import unescape
    from urllib.parse import unquote
    result = defaultdict(set)
    regs = {
        'mail': r'[\w\-][\w\-\.]+@[\w\-][\w\-]+\.[^0-9\W]{1,5}',
        'phone': r'\+\d[-()\s\d]{5,}?(?=\s*[+<])',
        'tel': r'tel:(\+?[^\'"<>]+)',
        'mailto': r'mailto:(\+?[^\'"<>]+)',
    }
    contacts = defaultdict(set)
    for name, reg in regs.items():
        for m in re.findall(reg, html):
            if m.endswith(('png', 'svg')):
                continue
            contacts[name].add(m)
    for n, cc in contacts.items():
        for c in cc:
            v = unquote(unescape(c))
            result[n].add(v)
    return result


class LinkedDomainsParser(HTMLParser):
    def __init__(self, src_domain=None):
        super().__init__()
        self.src_domain = src_domain
        self.result = defaultdict(set)

    def handle_starttag(self, tag, attrs):
        from urllib.parse import urlparse
        for name, value in attrs:
            if name in ['href', 'src']:
                pu = urlparse(value)
                if pu and pu.hostname and pu.hostname != self.src_domain:
                    self.result[f'<{tag}>'].add(pu.hostname)


def get_linked_domains(html, src_domain=None):
    parser = LinkedDomainsParser(src_domain)
    parser.feed(html)
    return parser.result
