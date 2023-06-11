#!/usr/bin/env python3

"""
Author :- @p00rduck (poorduck)
Date :- 2023-06-10
Version: v0.0.1
Description :- In the current state this script can download older versions of an app available on 'apkpure.com' (Not including the latest version available on apkpure.com)

Requirements :-

beautifulsoup4==4.12.2
cfscrape==2.1.1
rich==13.4.1
"""

import argparse
import os
from bs4 import BeautifulSoup
from time import sleep
from rich.console import Console
import concurrent.futures
import cfscrape  # https://github.com/Anorov/cloudflare-scrape

def extract_download_links(url, package_uri, package_name):

    global scraper, console

    ver_download_urls = []
    filename = package_name + "-downloads.txt"

    if os.path.exists(filename):
        print("[+] Download links file already exists.")
        with open(filename, 'r') as fr:
            ver_download_urls = fr.read().split('\n')
        return ver_download_urls

    # Extract all versions download URLs
    print("[+] Extracting download links, please wait...")
    response = scraper.get(url + package_uri + "/versions").text
    soup = BeautifulSoup(response, "html.parser")

    versions_elements_div = soup.find("ul", class_="ver-wrap")
    versions_elements_li = versions_elements_div.findAll("li", recursive=False)
    href_list = [li.find("a", class_="ver_download_link")["href"] if li.find("a", class_="ver_download_link") else None for li in versions_elements_li]

    try:
        with console.status("[bold green]Working on it...") as status:
            for href_link in href_list:
                
                if href_link is not None:
                    download_page = scraper.get(href_link).text
                    if "Download Variant" in download_page:
                        console.log("[yellow]Found multiple variants for " + href_link.split("/")[-1] + "[/yellow]")
                        soup = BeautifulSoup(download_page, "html.parser")
                        variants = soup.findAll("div", class_="table-cell down")
                        variants_uris = [div.find('a')['href'] for div in variants]
                        for variant in variants_uris:
                            variant_download_page = scraper.get(url + variant).text
                            soup = BeautifulSoup(variant_download_page, "html.parser")
                            download_btn_element = soup.find("a", class_="download-start-btn")
                            variant_download_url = download_btn_element['href']
                            ver_download_urls.append(variant_download_url)
                            # sleep(5)  # Keep it slow
                    else:
                        soup = BeautifulSoup(download_page, "html.parser")
                        download_btn_element = soup.find("a", class_="download-start-btn")
                        download_url = download_btn_element['href']
                        ver_download_urls.append(download_url)
                        # sleep(5)  # Keep it slow

    except KeyboardInterrupt as e:
        print(e)
    except Exception as e:
        if ver_download_urls is None:
            exit("[-] Not found!")
        else:
            return list(set(ver_download_urls))
    finally:
        with open(filename, 'w') as fw:
            for url in list(set(ver_download_urls)):
                fw.write("%s\n" % url)
    
    return list(set(ver_download_urls)) # In some cases, it appears that the apkpure provides the same APK file for all variants (?)


def main():
    
    # Parse required argument(s) for the script.
    parser = argparse.ArgumentParser(description='Download all versions of an Android mobile application from apkpure.com')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-p', required=True, metavar="packagename", help="example: com.twitter.android")
    parser.add_argument('-nd', action='store_false', default=True, help="Disable downloading, only extract download links.")
    args = parser.parse_args()

    # Init cloudflare scrapper.
    global scraper, console

    scraper = cfscrape.create_scraper(delay=10)
    console = Console()

    base_url = "https://apkpure.com"
    package_name = args.p

    console.log("[bold green]Target APK - " + package_name + "[/bold green]")
    package_uri = ""
    
    max_retries = 5  # Maximum number of retries
    retry_count = 0

    while retry_count < max_retries:
        try:
            response = scraper.get(f"{base_url}/search?q=" + package_name).text
        except KeyboardInterrupt:
            exit()
        except Exception as e:
            exit(e)

        if "Cloudflare Ray ID" in response:
            print("Cloudflare protection could not be bypassed, trying again..")
            sleep(5)  # Keep it slow
            retry_count += 1
            continue

        elif "Cloudflare Ray ID" not in response:
            soup = BeautifulSoup(response, 'html.parser')
            element = soup.find('a', class_='first-info')

            if element is not None:
                package_uri = element['href']
                print("[+] Found package -", package_uri)
                break

        elif retry_count == max_retries:
            print("[-] Failed to bypass Cloudflare protection.")
            return
        
        else:
            print("Package not found!")
            return
        
    
    links = extract_download_links(url=base_url, package_uri=package_uri, package_name=package_name)

    def _download_apk(url):

        current_directory = os.getcwd()
        final_directory = os.path.join(current_directory, package_name)

        if not os.path.exists(final_directory):
            os.makedirs(final_directory)

        filename = url.split("/")[-1].replace("?", "-").replace("=", "_") + ".apk"

        if os.path.exists(os.path.join(package_name, filename)):
            console.print("[yellow]... " + filename + " is already exists.[/yellow]")
            return False

        print("... " + filename + " is downloading, please wait...")
        file = scraper.get(url)
        open(os.path.join(package_name, filename), "wb").write(file.content)

        return True

    num_threads = 4  # Adjust this value based on the desired number of parallel downloads
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)

    if args.nd:
        try:
            with console.status("[bold green]Working on it...") as status:
                download_tasks = [executor.submit(_download_apk, link) for link in links[:-1] if link is not None]
                concurrent.futures.wait(download_tasks)
                any_file_downloaded = False
                for task in concurrent.futures.as_completed(download_tasks):
                    if task.result():
                        any_file_downloaded = True

                if not any_file_downloaded:
                    print("[!] Nothing new!")

        except KeyboardInterrupt:
            print("[!] Keyboard interruption detected. we'll shutdown execution after running threads are finished.")
            sleep(2)
            print("... Promise!")
            executor.shutdown(cancel_futures=True)

    console.log("[bold green]Done![/bold green]")


if __name__ == "__main__":

    main()
