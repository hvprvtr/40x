#!/usr/bin/python3
import random
import re
import os
import time
import urllib3
import requests
import argparse
from termcolor import cprint

#TODO multithreading by param, default - false

def file_to_list(fpath):
    result = []
    with open(fpath) as fh:
        for line in fh:
            line = line.strip()
            if not len(line) or line.startswith("#"):
                continue
            result.append(line)
    return result


COLOR_RED = "red"
COLOR_GREEN = "green"
COLOR_YELLOW = "yellow"
COLOR_BLUE = "blue"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Check URL for 401/403 code bypass possibility')
parser.add_argument('-u', '--url', help="Target URL / file with URLs", required=True)
parser.add_argument('-i', '--ip', help="IP or file with IPs for headers substitution", default="ips.txt")
parser.add_argument('-c', '--code', help="Which code we bypass?", required=True, type=int)
parser.add_argument('-e', '--header', help="Header name for substitution, or file with it", default="headers.txt")
parser.add_argument('-a', '--user-agent', help="User-Agent value", default="Mozilla/5.0")
parser.add_argument('-l', '--logfile', help="Log file name", default="log.txt")
parser.add_argument('-d', '--debug', default=False, action='store_true')


args = parser.parse_args()

urls = set()
if args.url.startswith("http://") or args.url.startswith("https://"):
    urls.add(args.url)
else:
    if not os.path.exists(args.url):
        cprint("Error! File with urls '{0}' not exists.".format(args.url), COLOR_RED)
        exit(0)
    urls.update(file_to_list(args.url))

headers = set()
if re.match('^[a-z\-0-9]+$', args.header, re.I):
    headers.add(args.url)
else:
    if not os.path.exists(args.header):
        cprint("Error! File with headers '{0}' not exists.".format(args.header), COLOR_RED)
        exit(0)
    headers.update(file_to_list(args.header))

ips = set()
if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', args.ip):
    ips.add(args.ip)
else:
    if not os.path.exists(args.ip):
        cprint("Error! File with IPs '{0}' not exists.".format(args.ip), COLOR_RED)
        exit(0)
    ips.update(file_to_list(args.ip))


def get_response(url, header_name, ip, retries=0):
    if args.debug:
        cprint("Try {0} {1}: {2}".format(url, header_name, ip), COLOR_BLUE)

    if retries > 5:
        cprint("{0}: {1} => FAIL by exceptions".format(header_name, ip), COLOR_YELLOW)
        return None, None

    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={'User-Agent': args.user_agent, header_name: ip},
                            allow_redirects=False)
        return resp.status_code, resp.text
    except BaseException as e:
        time.sleep(random.randint(1, 3))
        if args.debug:
            cprint("{0}: {1} => E: {2}".format(header_name, ip, str(e)), COLOR_BLUE)
        return get_response(url, header_name, ip, retries + 1)

    return None, None


def check_header_value(url, header_name, value):
    code, text = get_response(url, header_name, value)
    if code == int(args.code) or code is None:
        return

    with open("log.txt", "a") as fh:
        fh.write("{0} {1} {2}\n".format(url, header_name, value))

    cprint("Found! {0}: {1} got code {2}".format(header_name, value, code), COLOR_GREEN)

    tmp = url + '_' + header_name + "_" + value + ".txt"
    fname = re.sub('[^a-z0-9\.\-_]+', '_', tmp, re.I)
    with open("responses/" + fname, 'w') as fh:
        fh.write(text)

    cprint("Response wrote in {0}".format("responses/" + fname), COLOR_GREEN)


cprint("Start working. We got {0} ips and {1} headers for {2} urls. Tries await: {3}".format(
    len(ips), len(headers), len(urls), len(ips) * len(headers) * len(urls)
), COLOR_GREEN)

for url in urls:
    try:
        resp = requests.get(url,
                            verify=False, timeout=5, headers={'User-Agent': args.user_agent},
                            allow_redirects=False)
        if resp.status_code != int(args.code):
            cprint("URL {0} got code {1}, but you wanna bypass {2}".format(url, resp.status_code, args.code))
            exit(0)
    except BaseException as e:
        cprint("{0} check error: {1}".format(url, str(e)))
        exit(1)

for url in urls:
    for header in headers:
        for ip in ips:
            check_header_value(url, header, ip)

    check_header_value(url, "Host", "localhost")

cprint("Done", COLOR_GREEN)

