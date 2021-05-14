def reverse_dns(ip):
    from socket import gethostbyaddr
    try:
        return gethostbyaddr(ip)[0]
    except:
        return


def geoip_str_online(ip):
    import requests
    url = 'https://ipinfo.io/%s/json' % ip
    try:
        d = requests.get(url).json()
        if d:
            return '%s, %s, %s' % (d.get("country"), d.get("region"), d.get("city"))
    except:
        pass
    return ''


def tim():
    from datetime import datetime
    return datetime.now().strftime('%H:%M:%S')


def get_domains_from_cert(hostname, port: int = 443, timeout: float = 10) -> list:
    import ssl
    import socket

    context = ssl.create_default_context()
    context.check_hostname = False
    # context.verify_mode = ssl.VerifyMode.CERT_NONE

    try:
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as c:
            c.settimeout(timeout)
            c.connect((hostname, port))

            ssl_info = c.getpeercert()

            return [v for _, v in ssl_info.get('subjectAltName', [])]
    except:
        pass

    return []
