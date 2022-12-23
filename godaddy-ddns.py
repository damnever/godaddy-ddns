#!/usr/bin/env python3
'''
Usage:
    python godaddy-ddns.py --domain *.example.com --ip-resolvers https://checkip.amazonaws.com/ --api-key KEY:SECRET

GoDaddy API doc: https://developer.godaddy.com/doc/endpoint/domains
GoDaddy API keys: https://developer.godaddy.com/keys/
'''

import json
import argparse
from urllib.request import urlopen, Request


def do_http(url, method, headers={}, data=None, raise_if_not=(200, )):
    req = Request(url, method=method, data=data)
    for k, v in headers.items():
        req.add_header(k, v)
    with urlopen(req, timeout=30) as f:
        resp = f.read().decode("utf-8")
        if f.status not in raise_if_not:
            raise RuntimeError(
                "{} {}: {} {}: {}", method, url, f.status, f.reason, resp
            )
        # print(method, url, headers, data, resp)
        return resp


def do_http_godaddy(url, method, api_key_secret, data=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "sso-key {}".format(api_key_secret),
    }
    resp = do_http(url, method, headers, data=data, raise_if_not=(200, 404))
    if not resp:
        return resp
    return json.loads(resp)


def fetch_domain_record(api_key_secret, domain, name):
    url = 'https://api.godaddy.com/v1/domains/{}/records/A/{}'.format(
        domain, name
    )
    resp = do_http_godaddy(url, "GET", api_key_secret)
    if not isinstance(resp, list) or len(resp) == 0:
        return ""
    return resp[0]["data"]


def create_domain_record(api_key_secret, domain, name, ip, ttl):
    url = 'https://api.godaddy.com/v1/domains/{}/records'.format(domain)
    data = json.dumps([{
        "data": ip,
        "ttl": ttl,
        "name": name,
        "type": "A"
    }]).encode("utf-8")
    return do_http_godaddy(url, "PATCH", api_key_secret, data)


def update_domain_record(api_key_secret, domain, name, ip, ttl):
    url = 'https://api.godaddy.com/v1/domains/{}/records/A/{}'.format(
        domain, name
    )
    data = json.dumps([{"data": ip, "ttl": ttl}]).encode("utf-8")
    return do_http_godaddy(url, "PUT", api_key_secret, data)


parser = argparse.ArgumentParser(description='GoDaddy Dynamic DNS.')
parser.add_argument(
    '--domain',
    dest='domain',
    type=str,
    help='Fully-qualified domain name, supports wildcard domain as well.'
)
parser.add_argument(
    '--ip',
    dest='ip',
    type=str,
    default='',
    help='The public IP address, use --ip-resolvers to detect it automatically.'
)
parser.add_argument(
    '--ip-resolvers',
    dest='ip_resolvers',
    type=str,
    nargs='*',
    default=['https://checkip.amazonaws.com/', 'https://ifconfig.me/ip'],
    help=
    'Get the public IP from providers, such as https://checkip.amazonaws.com/.'
)
parser.add_argument(
    '--api-key',
    dest='api_key',
    type=str,
    default='',
    help='GoDaddy API key, format like this: `key:secret`.'
)
parser.add_argument('--ttl', type=int, default=600, help='DNS TTL in seconds.')
args = parser.parse_args()

domain = None
name = None
domain_parts = args.domain.split('.')
if len(domain_parts) < 2:
    msg = '"{}" is not a fully-qualified domain name.'.format(args.domain)
    raise Exception(msg)
elif len(domain_parts) < 3:
    domain = args.domain
    name = "@"
else:
    domain = ".".join(domain_parts[-2:])
    name = ".".join(domain_parts[:-2])

ip = args.ip
if not args.ip:
    for url in args.ip_resolvers:
        try:
            ip = do_http(url, "GET").strip()
        except Exception as e:
            print('Get IP from {} failed: {}'.format(url, ip))
    if not ip:
        raise Exception("No IP address found")
gdd_api_key = args.api_key
ttl = args.ttl

print('A RECORD: domain={} name={} ip={} ttl={}'.format(domain, name, ip, ttl))
previous_ip = fetch_domain_record(gdd_api_key, domain, name)
if previous_ip == ip:
    print('IP is the same, skip...'.format(previous_ip))
else:
    if previous_ip == "":
        do_func = create_domain_record
        print('Create a new record...')
    else:
        do_func = update_domain_record
        print('Update the existing record...')
    do_func(gdd_api_key, domain, name, ip, ttl)
    print("DONE")
