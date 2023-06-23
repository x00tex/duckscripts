#!/usr/bin/env python3

"""
Author :- @p00rduck (poorduck)
Date :- 2023-06-20
Version: v0.0.1-Alpha
Description :- Download android apks from apkpure and and run through apileaks.

Requirements :-

    beautifulsoup4==4.12.2
    cfscrape==2.1.1
    rich==13.4.1
    apkleaks==2.6.1
    python-magic==0.4.27

Known error and possible fixes :-

- ImportError: cannot import name 'DEFAULT_CIPHERS' from 'urllib3.util.ssl_'

    pip install 'urllib3<2'  

Quality Tweaks :-

- Suppress jadx output from "apkleaks==2.6.1" while it is decompile().
  - find "/apkleaks/apkleaks.py" location
    - Try this command - python -c "import site, sys; print('\n'.join(p for p in sys.path if p.endswith('site-packages')))"
  - Import "subprocess" in /apkleaks/apkleaks.py, and
  - Replace "os.system(comm)" in decompile() function with "subprocess.call(f"{comm} > /dev/null 2>&1", shell=True)".

"""


import argparse
import os
from bs4 import BeautifulSoup
from time import sleep
from rich.console import Console
import concurrent.futures
import cfscrape  # https://github.com/Anorov/cloudflare-scrape
import argparse
from apkleaks.apkleaks import APKLeaks
import magic
import zipfile
import tempfile
import sys
from io import StringIO


class APKLeaksRunner:
    def __init__(self, subArgs):
        self.args = subArgs
        self.init = None

    def _run(self, inputarg, outputarg):
        self.args.file = inputarg
        self.args.output = outputarg
        self.init = APKLeaks(self.args)

        try:
            # "/dev/null" for stdout and stderr
            dummy_stream = StringIO()  # Create a dummy file-like object to redirect stdout and stderr
            # Redirect to the dummy object
            sys.stdout = dummy_stream
            sys.stderr = dummy_stream

            self.init.integrity()
            self.init.decompile()
            self.init.scanning()
        finally:
            self.init.cleanup()

            # Restore to its original value
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

    def apkleaks(self, apk, ftype):
                output_file = apk + "-apkleaks.txt"

                if "Zip archive data" in ftype:
                    with tempfile.TemporaryDirectory() as temp_dir:

                        # Extract APK files form XAPK.
                        with zipfile.ZipFile(apk, 'r') as zip_ref:
                            for file_info in zip_ref.infolist():
                                if file_info.filename.endswith(".apk"):
                                    zip_ref.extract(file_info, temp_dir)

                        # Running APKLeaks on all APK files
                        extracted_files = os.listdir(temp_dir)
                        for file_name in extracted_files:
                            file_path = os.path.join(temp_dir, file_name)
                            apkLeakOut = file_path + "-apkleaks.txt"
                            try:
                                self._run(inputarg=file_path, outputarg=apkLeakOut)
                            except Exception as e:
                                pass

                        # Save all APK files output in one file.
                        apkleaksout_files = os.listdir(temp_dir)
                        with open(output_file, "w") as output:
                            for file_name in apkleaksout_files:
                                if file_name.endswith("-apkleaks.txt"):
                                    file_path = os.path.join(temp_dir, file_name)
                                    with open(file_path, "r") as file:
                                        content = file.read()

                                    output.write(f"--- {file_name} ---\n")
                                    output.write(content)
                                    output.write("\n\n")

                else:
                    try:
                        self._run(inputarg=apk, outputarg=output_file)
                    except Exception as e:
                        pass


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

    subparsers = parser.add_subparsers(dest='tool', metavar='OPTION', help='Choose the analysis tool ["apkleaks"]')

    apkleaks_parser = subparsers.add_parser('apkleaks', help='Run APKLeaks tool')
    apkleaks_parser.add_argument("-f", "--file", type=str, required=False, help=argparse.SUPPRESS)
    apkleaks_parser.add_argument("-o", "--output", type=str, required=False, help=argparse.SUPPRESS)
    apkleaks_parser.add_argument("-p", "--pattern", help="Path to custom patterns JSON", type=str, required=False)
    apkleaks_parser.add_argument("-a", "--args", help="Disassembler arguments (e.g. \"--threads-count 5 --deobf\")", type=str, required=False)
    apkleaks_parser.add_argument("--json", help="Save as JSON format", required=False, action="store_true")

    args = parser.parse_args()

    # Init cloudflare scrapper.
    global scraper, console

    scraper = cfscrape.create_scraper(delay=10)
    console = Console()

    base_url = "https://apkpure.com"
    package_name = args.p

    console.print("[bold green][+] Target APK - " + package_name + "[/bold green]")
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
                if package_name not in package_uri:
                    console.print("[bold red][-] Package Not Found![/bold red]")
                    exit(2)

                print("[+] Found package -", package_uri)
                break

        elif retry_count == max_retries:
            print("[-] Failed to bypass Cloudflare protection.")
            return
        
        else:
            print("Package not found!")
            return


    def _download_apk(url):

        current_directory = os.getcwd()
        final_directory = os.path.join(current_directory, package_name)

        if not os.path.exists(final_directory):
            os.makedirs(final_directory)

        filename = url.split("/")[-1].replace("?", "-").replace("=", "_")

        # Check if file is APK or XAPK bundle.
        if "XAPK" in url:
            filename = filename + ".xapk"
        else:
            filename = filename + ".apk"

        absoluteFile = os.path.join(final_directory, filename)

        if os.path.exists(absoluteFile):
            console.print("[yellow]... " + filename + " is already exists.[/yellow]")
            return False

        with console.status("[bold green]Working on it...") as status:
            print("... " + filename + " is downloading, please wait...")
            file = scraper.get(url)
            open(absoluteFile, "wb").write(file.content)
            
            file_type = magic.from_file(absoluteFile)

            if args.tool == 'apkleaks':
                console.log("[yellow]APKLeaks :-[/yellow]", filename)
                apkleaksrunner = APKLeaksRunner(subArgs=args)
                apkleaksrunner.apkleaks(apk=absoluteFile, ftype=file_type)

        return True

    links = extract_download_links(url=base_url, package_uri=package_uri, package_name=package_name)

    # DO NOT CHANGE THE VALUE IF YOU WANT TO RUN APKLEAKS.
    num_threads = 1  # Adjust this value based on the desired number of parallel downloads
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)

    if args.nd:
        try:
            download_tasks = [executor.submit(_download_apk, link) for link in links if link is not None]
            concurrent.futures.wait(download_tasks)
            any_file_downloaded = False
            for task in concurrent.futures.as_completed(download_tasks):
                if task.result():
                    any_file_downloaded = True

            if not any_file_downloaded:
                print("[!] Nothing new!")

        except KeyboardInterrupt:
            print("\n[!] Keyboard interruption detected. we'll shutdown execution after running threads are finished.")
            sleep(2)
            print("... Promise!")
            executor.shutdown(cancel_futures=True)
        except Exception as e:
            exit(e)

    console.print("[bold green][+] Done![/bold green]")


if __name__ == "__main__":

    main()
