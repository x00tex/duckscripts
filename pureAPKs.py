#!/usr/bin/env python3

"""
Author :- @p00rduck (poorduck)
Date :- 2023-06-10
Update :- 2023-06-23
Version: v0.0.2
Description :- Multi threaded android application downloader from apkpure.com.

Requirements :-
    rich==13.4.1
"""

import argparse
import os
from time import sleep as wait
from rich.console import Console
import concurrent.futures
import requests
import json
import pathlib


def apkpureAPIScrapper(url, package_name):

    global console, apiScrapper, downloadLinksJSON

    headers = {
    "User-Agent-Webview": "Mozilla/5.0 (Linux; Android 8.1.0; Pixel Build/OPM6.171019.030.E1; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.186 Mobile Safari/537.36",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 8.1.0; Pixel Build/OPM6.171019.030.E1); APKPure/3.18.66 (Aegon)",
    "Ual-Access-Businessid": "projecta",
    "Ual-Access-Projecta": "{\"device_info\":{\"abis\":[\"x86\",\"x86_64\",\"arm64-v8a\",\"armeabi-v7a\",\"armeabi\"],\"android_id\":\"127ccad528a8e541\",\"brand\":\"Google\",\"country\":\"United States\",\"country_code\":\"US\",\"imei\":\"000000000000000\",\"language\":\"en-US\",\"manufacturer\":\"Google\",\"mode\":\"Pixel\",\"os_ver\":\"27\",\"os_ver_name\":\"8.1.0\",\"platform\":1,\"product\":\"Pixel\",\"screen_height\":1920,\"screen_width\":1080}}"
    }

    uri = "/v3/get_app_his_version"
    param = {"package_name": package_name}

    apiScrapper.headers = headers

    data = apiScrapper.get(url + uri, params=param)
    version_list = data.json()["version_list"]
    applications = []

    try:
        if version_list:
            for item in version_list:
                package_name = item["package_name"]
                version_code = item["version_code"]
                version_name = item["version_name"]
                url_seed = item["asset"]["url_seed"] # Using seed url for downloading app instead of "url".
                type = item["asset"]["type"]
                new_item = {
                    'filename': package_name + "-" + version_name + "-versionCode_" + version_code + "." + type.lower(),
                    'download_url': url_seed
                }
                if not any(entry["filename"] == new_item["filename"] for entry in applications):
                    applications.append(new_item)
        else:
            console.print("[red][-] Package Not Found.[/red]")
            exit(1)
    except KeyboardInterrupt as e:
        exit(e)
    except Exception as e:
        exit(e)
    finally:
        data_to_save = json.dumps(applications)
        open(downloadLinksJSON, 'w').write(data_to_save)

    return applications


def main():
    
    # Parse required argument(s) for the script.
    parser = argparse.ArgumentParser(description='Download all versions of an Android mobile application from apkpure.com')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-p', required=True, metavar="packagename", help="example: com.twitter.android")
    parser.add_argument('-nd', action='store_false', default=True, help="Disable downloading, only extract download links.")
    args = parser.parse_args()

    global apiScrapper, console, packageName, downloadLinksJSON

    apiScrapper = requests.session()
    console = Console()
    packageName = args.p
    downloadLinksJSON = packageName + "-downloadlinks.json"

    console.print("[bold green][+] Target APK - " + packageName + "[/bold green]")

    base_url = "https://tapi.pureapk.com"
    bigData = []

    if os.path.exists(downloadLinksJSON) and os.path.getsize(downloadLinksJSON) != 2:
        console.print("[yellow][!] Download links file already exists.[/yellow]")
        with open(downloadLinksJSON, 'r') as fr:
            bigData = json.loads(fr.read())
    else:
        print("[+] Scrapping download links.")
        with console.status("[bold green]Scrapping...") as status:
            bigData = apkpureAPIScrapper(url=base_url, package_name=packageName)


    def _download_apk(url, filename):

        current_directory = os.getcwd()
        final_directory = os.path.join(current_directory, packageName)

        if not os.path.exists(final_directory):
            os.makedirs(final_directory)

        absoluteFile = os.path.join(final_directory, filename)

        if os.path.exists(absoluteFile):
            console.print("[yellow]... " + filename + " is already exists.[/yellow]")
            return False

        # Do not download "xapk" files. 
        if pathlib.Path(filename).suffix == ".xapk":
            console.print("[yellow]... Skipping " + filename + " [/yellow]")
            return False

        print("... " + filename + " is downloading, please wait...")
        file = apiScrapper.get(url)
        open(absoluteFile, "wb").write(file.content)

        return True

    num_threads = 4  # Adjust this value based on the desired number of parallel downloads
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)

    if args.nd:
        try:
            with console.status("[bold green]Downloading in process...") as status:
                download_tasks = [executor.submit(_download_apk, data["download_url"], data["filename"]) for data in bigData]
                concurrent.futures.wait(download_tasks)
                any_file_downloaded = False
                for task in concurrent.futures.as_completed(download_tasks):
                    if task.result():
                        any_file_downloaded = True

                if not any_file_downloaded:
                    print("[!] Nothing new!")

        except KeyboardInterrupt:
            console.print("[yellow][!] Keyboard interruption detected. we'll shutdown execution after running threads are finished.[/yellow]")
            wait(2)
            print("... Promise!")
            executor.shutdown(cancel_futures=True)

    console.print("[bold green][+] Done![/bold green]")


if __name__ == "__main__":

    main()
