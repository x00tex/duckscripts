#!/usr/bin/env python3

"""
Author :- @p00rduck (Poorduck)
Date :- 2023-06-20

Update :- 2023-07-10
    - apkID output saved in txt file
    - added xnlinkfinder in apkflow

Version: v0.0.2-Beta
Description :- Download android APK(s) from APKPure and and run through APKLeaks.

Requirements :-

    beautifulsoup4==4.12.2
    cfscrape==2.1.1
    rich==13.4.1
    apkleaks==2.6.1
    python-magic==0.4.27
    apkid==2.1.1

Known error and possible fixes :-

- ImportError: cannot import name 'DEFAULT_CIPHERS' from 'urllib3.util.ssl_'

    pip install 'urllib3<2'

- yara.Error: internal error: 34

    pip install -U git+https://github.com/MobSF/yara-python-dex

Quality Tweaks :-

- Suppress jadx output from "apkleaks==2.6.1" while it is decompile().
  - find "/apkleaks/apkleaks.py" location
    - Try this command - python -c "import site, sys; print('\n'.join(p for p in sys.path if p.endswith('site-packages')))"
  - Import "subprocess" in /apkleaks/apkleaks.py, and
  - Replace `os.system(comm)` in decompile() function with `subprocess.call(f"{comm} > /dev/null 2>&1", shell=True)`.

- If you want to run xnl and apkleaks together, by default it will run jadx twice, to fix this, replace decompile() func from /apkleaks/apkleaks.py -

	def decompile(self, save_dis: str = None):
		util.writeln("** Decompiling APK...", col.OKBLUE)
		args = [self.jadx, self.file, "-d", self.tempdir]
		try:
			args.extend(re.split(r"\s|=", self.disarg))
		except Exception:
			pass
		comm = "%s" % (" ".join(quote(arg) for arg in args))
		comm = comm.replace("\'","\"")
		# os.system(comm)
		subprocess.call(f"{comm} > /dev/null 2>&1", shell=True)

		if save_dis:
			source_dir = self.tempdir
			destination_dir = save_dis
			os.system(f'cp -r {source_dir}/resources {source_dir}/sources {destination_dir}')
		else:
			pass

"""

def init_script__():
    
    failed_modules = []

    for module in [
        'bs4',
        'magic',
        'rich',
        'cfscrape',
        'apkleaks.apkleaks',
        'apkid.apkid',
        'shutil'
    ]:
        try:
            __import__(module)
        except ModuleNotFoundError as e:
            failed_modules.append(str(e.name))

    if failed_modules:
        print("[-] Modules not found:", " ".join(failed_modules))
        exit()

    import shutil
    binaries = ["jadx", "xnlinkfinder"]
    not_found_binaries = []

    for binary in binaries:
        if shutil.which(binary) is None:
            not_found_binaries.append(binary)

    if not_found_binaries:
        print("[-] Binaries not found:", ", ".join(not_found_binaries))
        if "xnlinkfinder" in not_found_binaries:
            print("... Original xnLinkFinder does not installed properly with pip and script doesn't support scriptpath as input\n... Try installing \"xnlinkfinder\" from fork,  -\n\n      pip install git+https://github.com/x00tex/xnLinkFinder@pipx-update")
        exit()

init_script__()


import os
import re
import sys
import json
import magic
import shutil
import zipfile
import tempfile
import requests
import urllib3
import argparse
import subprocess
import concurrent.futures
from io import StringIO
from time import sleep as wait
from pipes import quote
from contextlib import redirect_stdout
from bs4 import BeautifulSoup
from rich.console import Console
import cfscrape  # https://github.com/Anorov/cloudflare-scrape
from apkleaks.apkleaks import APKLeaks  # https://github.com/dwisiswant0/apkleaks
from apkid.apkid import Scanner, Options  # https://github.com/rednaga/APKiD


class APKLeaksRunner:
    def __init__(self, subArgs, jadx_output: str = None):
        self.args = subArgs
        self.init = None
        self.outdir = jadx_output

    def _run(self, inputarg, outputarg):
        self.args.file = inputarg
        self.args.output = outputarg
        self.init = APKLeaks(self.args)

        try:
            original_stdout = sys.stdout  # Store the original sys.stdout in a variable
            dummy_stream = StringIO()  # Create a dummy file-like object to redirect stdout and stderr

            with redirect_stdout(dummy_stream):
                try:
                    self.init.integrity()

                    if self.outdir:
                        try:
                            self.init.decompile(save_dis=self.outdir)
                        except TypeError:
                            self.init.decompile()
                    else:
                        self.init.decompile()

                    self.init.scanning()

                finally:
                    self.init.cleanup()
        finally:
            sys.stdout = original_stdout  # Restore sys.stdout to its original value

    def apkleaks(self, apkfile: str, ftype: str):
        output_file = f"{self.outdir}/apkleaks.txt"

        if os.path.exists(output_file):
            console.log("... [yellow]APKLeaks[/yellow] :- [bold yellow]skipping[/bold yellow]")
            return

        if "Zip archive data" in ftype:
            with tempfile.TemporaryDirectory() as temp_dir:

                # Extract APK files form XAPK.
                with zipfile.ZipFile(apkfile, 'r') as zip_ref:
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
                self._run(inputarg=apkfile, outputarg=output_file)
            except Exception as e:
                return False


class APKiDRunner:
    def __init__(self):
        self.options = None
        self.scanner = None

    def _build_options(self):
        return Options(
            verbose=False,  # log debug messages
            json=False,  # output scan results in JSON format
            output_dir=None,  # write individual results here (implies --json)
            include_types=False,  # include file type info for matched files
            timeout=30,  # Yara scan timeout (in seconds)
            recursive=False,  # recurse into subdirectories
            scan_depth=2,  # how deep to go when scanning nested zips, 2 is enought for xapk
            entry_max_scan_size=100 * 1024 * 1024,  # max zip entry size to scan in bytes, 0 = no limit
            typing="magic"  # method to decide which files to scan, choices = ('magic', 'filename', 'none')   
        )

    def run(self, apkfile: str, out_dir: str):

        global console

        output_file = f"{out_dir}/apkid.txt"

        if os.path.exists(output_file):
            console.log("... [yellow]ApkID[/yellow] :- [bold yellow]skipping[/bold yellow]")
            return
        
        try:
            original_stdout = sys.stdout  # Store the original sys.stdout in a variable
            dummy_stream = StringIO()  # Create a dummy file-like object to redirect stdout and stderr

            with redirect_stdout(dummy_stream):
                self.options = self._build_options()
                rules = self.options.rules_manager.load()
                self.scanner = Scanner(rules, self.options)

                self.scanner.scan(apkfile)

            # Get the content from the dummy_stream
            output = dummy_stream.getvalue()
            lines = output.split('\n')
            printout = False
            if printout:
                console.log("... [yellow]ApkID[/yellow] :-", apkfile.split("/")[-1])
                for line in lines:
                    console.log(line)
            else:
                with open(output_file, "w") as f:
                    f.writelines(lines)

        finally:
            sys.stdout = original_stdout  # Restore sys.stdout to its original value


class XNLRunner:
    def __init__(self, apkfile: str, package_name: str, xnl_out: str, jadx_out: str, jadx_path: str = shutil.which('jadx')):
        self.apk = apkfile
        self.jadx = jadx_path
        self.jadxdir = jadx_out  # tempfile.mkdtemp()
        self.xnlout = xnl_out
        self.packagedir = package_name.replace(".", "/")
        self.xnl = "xnlinkfinder"

    # This function is taken form "apkleaks"
    def _decompile(self):
        disarg = "--threads-count 1"
        args = [self.jadx, self.apk, "-d", self.jadxdir]
        try:
            args.extend(re.split(r"\s|=", disarg))
        except Exception:
            pass
        comm = "%s" % (" ".join(quote(arg) for arg in args))
        comm = comm.replace("\'","\"")
        # os.system(comm)
        subprocess.call(f"{comm} > /dev/null 2>&1", shell=True)

    def run(self, run_jadx: bool = False):
        output_file = f"{self.xnlout}/xnlinkfinder.txt"
        if os.path.exists(output_file):
            console.log("... [yellow]xnLinkFinder[/yellow] :- [bold yellow]skipping[/bold yellow]")
            return
        
        if run_jadx:
            self._decompile()

        if not os.path.exists(f"{self.jadxdir}/sources"):  # "jadx Decompiled Source Not Found!"
            self._decompile() 

        args = [self.xnl, "-i", f"{self.jadxdir}/sources/{self.packagedir}/", "-nb", "-ascii-only", "-o", output_file, "-op", "/dev/null"]
        comm = "%s" % (" ".join(quote(arg) for arg in args))
        comm = comm.replace("\'","\"")
        # os.system(comm)
        subprocess.call(f"{comm} > /dev/null 2>&1", shell=True)


def apkpureWebScrapper(url, package_name):

    global _WEB_SCRAPPER, console, downloadLinksJSON

    package_uri = ""

    # Try to bypass Cloudflare.
    max_retries = 5  # Maximum number of retries
    retry_count = 0

    while retry_count < max_retries + 1:
        try:
            response = _WEB_SCRAPPER.get(f"{url}/search?q=" + package_name)

            if "Cloudflare Ray ID" in response.text:
                console.log("[yellow]Cloudflare protection could not be bypassed, trying again..[/yellow]")
                wait(5)  # Keep it slow
                if retry_count == max_retries:
                    console.print("[-] [red]Failed to Bypass Cloudflare Protection.[/red]")
                    exit(response.status_code)

                retry_count += 1
                continue
            elif response.status_code != 200:
                if retry_count == max_retries:
                    console.print("[-] [red]Failed to Bypass Cloudflare Protection.[/red]")
                    exit(response.status_code)

                retry_count += 1
                continue
            elif "Cloudflare Ray ID" not in response.text:
                soup = BeautifulSoup(response.text, 'html.parser')
                element = soup.find('a', class_='first-info')
                if element is not None:
                    package_uri = element['href']
                    if package_name not in package_uri:
                        console.print("[red][-] Package Not Found.[/red]")
                        exit(1)

                    print("[+] Found Package -", package_uri)
                    break
            else:
                console.print("[-] [red]Something Went Wrong.[/red]")
                exit(response.status_code)

        except KeyboardInterrupt as e:
            exit(e)
        except Exception as e:
            exit(e)


    applications = []

    # Extract all versions download URLs
    print("[+] Extracting download links, please wait...")
    response = _WEB_SCRAPPER.get(f"{package_uri}/versions").text
    soup = BeautifulSoup(response, "html.parser")

    ver_elements_div = soup.find("ul", class_="ver-wrap")
    ver_elements_li = ver_elements_div.findAll("li", recursive=False)
    ver_download_link = [li.find("a", class_="ver_download_link")["href"] if li.find("a", class_="ver_download_link") else None for li in ver_elements_li]

    try:
        for href_link in ver_download_link:
                
            if href_link is not None:
                download_page = _WEB_SCRAPPER.get(href_link).text
                if "Download Variant" in download_page:
                    console.log("[yellow]Found multiple variants for " + href_link.split("/")[-1] + "[/yellow]")
                    soup = BeautifulSoup(download_page, "html.parser")
                    variants = soup.findAll("div", class_="table-cell down")
                    variants_uris = [div.find('a')['href'] for div in variants]
                    for variant in variants_uris:
                        variant_download_page = _WEB_SCRAPPER.get(url + variant).text
                        soup = BeautifulSoup(variant_download_page, "html.parser")
                        download_btn_element = soup.find("a", class_="download-start-btn")
                        variant_download_url = download_btn_element['href']
                        # In some cases, it appears that the apkpure provides the same APK file for all variants (?)
                        if not any(entry["download_url"] == variant_download_url for entry in applications):
                            veriant_version = soup.find('span', class_='info-sdk').find('span').text
                            veriant_name = variant_download_url.split("/")[-1].replace("?", "-").replace("=", "_")
                            app_name = re.sub(r'^(.*?)(-versionCode_\d+)$', fr'\g<1>-{veriant_version}\g<2>', veriant_name)
                            if "XAPK" in variant_download_url:
                                app_name = app_name + ".xapk"
                            else:
                                app_name = app_name + ".apk"

                            applications.append({'filename': app_name, 'download_url': variant_download_url, 'version': veriant_version})
                            # wait(5)  # Keep it slow
                else:
                    soup = BeautifulSoup(download_page, "html.parser")
                    download_btn_element = soup.find("a", class_="download-start-btn")
                    download_url = download_btn_element['href']
                    # In some cases, it appears that the apkpure provides the same APK file for all variants (?)
                    if not any(entry["download_url"] == download_url for entry in applications):
                        version = soup.find('span', class_='info-sdk').find('span').text
                        name = download_url.split("/")[-1].replace("?", "-").replace("=", "_")
                        app_name = re.sub(r'^(.*?)(-versionCode_\d+)$', fr'\g<1>-{version}\g<2>', name)
                        if "XAPK" in download_url:
                            app_name = app_name + ".xapk"
                        else:
                            app_name = app_name + ".apk"

                        applications.append({'filename': app_name, 'download_url': download_url, 'version': version})
                        # wait(5)  # Keep it slow

    except KeyboardInterrupt as e:
        exit(e)
    except Exception as e:
        exit(e)
    finally:
        data_to_save = json.dumps(applications)
        open(downloadLinksJSON, 'w').write(data_to_save)
    
    return applications


def apkpureAPIScrapper(url, package_name):

    global _API_SCRAPPER, console, downloadLinksJSON

    headers = {
    "User-Agent-Webview": "Mozilla/5.0 (Linux; Android 8.1.0; Pixel Build/OPM6.171019.030.E1; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.186 Mobile Safari/537.36",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 8.1.0; Pixel Build/OPM6.171019.030.E1); APKPure/3.18.66 (Aegon)",
    "Ual-Access-Businessid": "projecta",
    "Ual-Access-Projecta": "{\"device_info\":{\"abis\":[\"x86\",\"x86_64\",\"arm64-v8a\",\"armeabi-v7a\",\"armeabi\"],\"android_id\":\"127ccad528a8e541\",\"brand\":\"Google\",\"country\":\"United States\",\"country_code\":\"US\",\"imei\":\"000000000000000\",\"language\":\"en-US\",\"manufacturer\":\"Google\",\"mode\":\"Pixel\",\"os_ver\":\"27\",\"os_ver_name\":\"8.1.0\",\"platform\":1,\"product\":\"Pixel\",\"screen_height\":1920,\"screen_width\":1080}}"
    }

    uri = "/v3/get_app_his_version"
    param = {"package_name": package_name}

    _API_SCRAPPER.headers = headers

    data = _API_SCRAPPER.get(url + uri, params=param)
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
                    'download_url': url_seed,
                    'version': version_name
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
    parser.add_argument('-nd', action='store_false', default=True, help="Disable downloading, only extract download links.")
    parser.add_argument('--apkid', action='store_true', default=False, help="Run apkID on every app.")
    parser.add_argument('--xnl', action='store_true', default=False, help="Run xnLinkFinder on every app on jadx source.")

    required = parser.add_argument_group('required arguments')
    required.add_argument('-p', required=True, metavar="packagename", help="example: com.twitter.android")

    subparsers = parser.add_subparsers(dest='tool', metavar='OPTION', help='Choose the analysis tool ["apkleaks"]')

    apkleaks_parser = subparsers.add_parser('apkleaks', help='Run APKLeaks tool. Use it in the END, because any argument after it treated as apkleaks args')
    apkleaks_parser.add_argument("-f", "--file", type=str, required=False, help=argparse.SUPPRESS)
    apkleaks_parser.add_argument("-o", "--output", type=str, required=False, help=argparse.SUPPRESS)
    apkleaks_parser.add_argument("-p", "--pattern", help="Path to custom patterns JSON", type=str, required=False)
    apkleaks_parser.add_argument("-a", "--args", help="Disassembler arguments (e.g. \"--threads-count 5 --deobf\"), (default threads-count set to 1)",
                                 type=str, required=False, default="--threads-count 1")
    apkleaks_parser.add_argument("--json", help="Save as JSON format", required=False, action="store_true")

    args = parser.parse_args()

    global _API_SCRAPPER, _WEB_SCRAPPER, console, downloadLinksJSON
    
    _API_SCRAPPER = requests.session()
    _WEB_SCRAPPER = cfscrape.create_scraper(delay=10)

    apiproxy = False
    if apiproxy:
        print("[*] Burp proxy is enabled.")
        _API_SCRAPPER.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _API_SCRAPPER.verify = False

    webproxy = False
    if webproxy:
        print("[*] Burp proxy is enabled.")
        _WEB_SCRAPPER.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _WEB_SCRAPPER.verify = False

    console = Console(log_path=False, log_time_format="[%H:%M:%S.%f]")
    packageName = args.p
    downloadLinksJSON = packageName + "-downloadlinks.json"

    console.print("[bold green][+] Target APK - " + packageName + "[/bold green]")

    api_url = "https://tapi.pureapk.com"
    web_url = "https://apkpure.com"
    url = ""
    scrapper = ""

    bigData = []

    if os.path.exists(downloadLinksJSON) and os.path.getsize(downloadLinksJSON) != 2:
        console.print("[yellow][!] Download links file already exists.[/yellow]")
        with open(downloadLinksJSON, 'r') as fr:
            bigData = json.loads(fr.read())
    else:
        print("[+] Scrapping download links.")
        with console.status("[bold green]Scrapping...") as status:

            try:
                try:
                    response = requests.get(api_url)
                    response.raise_for_status()  # Raises an exception for non-2xx status codes
                    url = api_url
                    scrapper = "API"
                except requests.exceptions.RequestException:  # Fallback to Web 
                    try:
                        response = requests.get(web_url, 
                                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"},
                                                timeout=10)
                        response.raise_for_status()
                        url = web_url
                        scrapper = "WEB"
                    except requests.exceptions.RequestException:
                        console.print("[bold red][-] APKPure is Not Reachable.[/bold red]")
                        exit(1)

                if scrapper == "API":
                    print("[+] Using APKPure API:", url)
                    bigData = apkpureAPIScrapper(url=url, package_name=packageName)
                elif scrapper == "WEB":
                    print("[+] Using APKPure WEB:", url)
                    bigData = apkpureWebScrapper(url=url, package_name=packageName)
                else:
                    console.print("[bold red][-] No Scrapper Found![/bold red]")
                    exit(1)
            except KeyboardInterrupt:
                exit(0)

    def _APKFLOW(url: str, filename: str, version: str):

        console.print("[+] Working on :-", "[yellow]"+filename+"[/yellow]")

        current_directory = os.getcwd()
        final_directory = os.path.join(current_directory, packageName, version)

        if not os.path.exists(final_directory):
            os.makedirs(final_directory)

        absoluteFile = os.path.join(final_directory, filename)

        if os.path.exists(absoluteFile):
            console.log("... " + filename + " [yellow] Already Exist.[/yellow]")
        else:
            with console.status("[bold green]Downloading...") as status:

                if scrapper == "API":
                    file = _API_SCRAPPER.get(url)
                elif scrapper == "WEB":
                    file = _WEB_SCRAPPER.get(url)

                if file.status_code != 200:
                    console.print(f"[red][-] File Not Found, Status Code - {file.status_code}[/red]")
                    return

                open(absoluteFile, "wb").write(file.content)

        file_type = magic.from_file(absoluteFile)

        if args.apkid:
            with console.status("[bold green]Running apkid...") as status:
                apkidrunner = APKiDRunner()
                apkidrunner.run(apkfile=absoluteFile, out_dir=final_directory)

        if args.xnl and args.tool:
            jadx_out_path = final_directory
            xnl_jadx = False
        else:
            jadx_out_path = None
            xnl_jadx = True

        if args.tool == 'apkleaks':
            with console.status("[bold green]Running apkleaks...") as status:
                wait(1)
                apkleaksrunner = APKLeaksRunner(subArgs=args, jadx_output=jadx_out_path)
                apkleaksrunner.apkleaks(apkfile=absoluteFile, ftype=file_type)

        if args.xnl:
            with console.status("[bold green]Running xnLinkFinder...") as status:
                xnlrunner = XNLRunner(apkfile=absoluteFile,
                                    jadx_out=final_directory,
                                    xnl_out=final_directory,
                                    package_name=packageName)
                xnlrunner.run(run_jadx=xnl_jadx)

        return True

    if args.nd:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)  # DO NOT CHANGE THE WORKERS VALUE.
        try:
            download_tasks = [executor.submit(_APKFLOW, data["download_url"], data["filename"], data["version"]) for data in bigData]
            concurrent.futures.wait(download_tasks)
            any_file_downloaded = False
            for task in concurrent.futures.as_completed(download_tasks):
                if task.result():
                    any_file_downloaded = True

            if not any_file_downloaded:
                print("[!] Nothing new!")

        except KeyboardInterrupt:
            try:
                console.print("[yellow][!] Keyboard interruption detected. We'll shutdown execution after running threads are finished.[/yellow]")
                wait(1)
                print("... Promise!")
                executor.shutdown(cancel_futures=True)
            except KeyboardInterrupt as e:
                console.print("\n[red][!] Keyboard interruption detected again. Exiting immediately...[/red]")
                os._exit(0)  # Forcefully terminate the process without raising further exceptions

    console.print("[bold green][+] Done![/bold green]")


if __name__ == "__main__":

    main()
