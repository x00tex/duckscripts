#!/bin/bash

#############################################################################################################
#                                                                                                           #
# Author: @p00rduck                                                                                         #
# Date: 2023-05-26                                                                                          #
# Version: v0.0.1-Alpha                                                                                     #
# Description: Bash script for subdomain enumeration using variety of tools -                               #
#                 chaosDB, Findomain, Subfinder, Amass, gitlab-subdomains, shuffledns, jldc.me, dnsx, httpx #
#                                                                                                           #
# Usage: bash subzero.sh -h                                                                                 #
#                                                                                                           #
#############################################################################################################


setup() {
  sudo apt install curl wget jq amass lolcat figlet golang
  sudo wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O /usr/share/wordlists/subzero-resolvers.txt
  echo "\n\n# Go path variables\nexport GOPATH=$HOME/go\nexport PATH=\$GOPATH/bin:\$PATH" |  tee -a $HOME/.zshrc $HOME/.bashrc
  mkdir -p $HOME/.local/bin
  wget https://github.com/Findomain/Findomain/releases/download/8.2.2/findomain-linux.zip && unzip findomain-linux.zip findomain -d $HOME/.local/bin && chmod +x $HOME/.local/bin/findomain && rm findomain*.zip
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install -v github.com/tomnomnom/unfurl@latest
  go install -v github.com/tomnomnom/anew@latest
  go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  go install -v github.com/gwen001/gitlab-subdomains@latest
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

}

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo "Options:"
  echo "  -d DOMAIN [REQUIRED]          Target domain OR list of domains"
  echo "  -o ORG [REQUIRED]             Target organization name"
  echo "  -w wordlists                  Custom wordlist of subdomain Bruteforce"
  echo "  -a ASN                        ASN number"
  echo "  -p                            Run httpx probe over found subdomains"
  echo "  -s                            setup require tools for the script"
  echo "  -h                            Print Help"
}

if [ $# -eq 0 ]; then
  usage
  exit 0
fi

while getopts ":d:o:l:a:hp" opt; do
  case ${opt} in
    d)
      domainName="${OPTARG}"
      ;;
    o)
      orgName="${OPTARG}"
      ;;
    w)
      sublist="${OPTARG}"
      ;;
    a)
      asn="${OPTARG}"
      ;;
    p)
      httpxProbe=true
      ;;
    s)
      setup
      exit 0
      ;;
    h)
      figlet -f slant "SubZero" | lolcat
      usage
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check if all require arguments are supplied
if [ -z "$domainName" ] & [ -z "$orgName" ]; then
  echo "Error: argument -d AND -o is required" >&2
  exit 1
fi

# Set color variables
green='\033[0;32m'
yellow='\033[1;33m'
nc='\033[0m' # No Color

# Print out user inputs with ASCII art and colors
divider=$(printf "%0.s-" {1..30})
# figlet -f slant "SubZero" | lolcat
printf "${green}%s${nc}\n" "$divider"
printf "${yellow}[+] Organization:${nc} %s\n${yellow}[+] Domain:${nc} %s\n${yellow}[+] Wordlist:${nc} %s\n${yellow}[+] ASN:${nc} %s\n" "$orgName" "$domainName" "$sublist" "$asn"
printf "${green}%s${nc}\n" "$divider"

subDomains() {

  # API keys required by different tools for finding subdomains
  local virustotal=""
  local securitytrails=""
  local gitlab=""
  
  local dnsResolver="/usr/share/wordlists/subzero-resolvers.txt"

  printf "${green}[+] chaosDB${nc}\n"
  # ChaosDB - https://chaos.projectdiscovery.io/
  chaosDB=$(curl -s https://chaos-data.projectdiscovery.io/index.json | jq -r --arg search "$(echo $orgName | tr '[:upper:]' '[:lower:]').zip" '.[] | select((tostring | ascii_downcase) | contains($search | ascii_downcase)) | .URL')
  if [ "$chaosDB" ]; then
    wget -q $chaosDB --timeout 10 && mkdir chaos.temp && unzip -qq *.zip -d chaos.temp
    cat chaos.temp/$domainName.txt | tee chaosdb-output.txt 1>/dev/null

    printf "${green}[!] Other root domains in chaosDB${nc}\n"
    for i in $(ls chaos.temp/)
    do
      if [[ ! "$i" =~ $domainName ]]; then
          printf "... $(echo $i | rev | cut -d. -f2- | rev | cut -d/ -f2)\n"
      fi
    done

    rm -rf chaos.temp *.zip 
  else
    echo "... NULL"
  fi

  printf "${green}[+] Findomain${nc}\n"
  # Findomain - https://github.com/Findomain/Findomain
  # Sources: Certspotter, Crt.sh, Virustotal, Sublist3r, Bufferover, Threatcrowd, AnubisDB, Urlscan.io, Archive.org, CTSearch, Threatminer.
  # Sources may require API key: Facebook**, Virustotal with apikey**, SecurityTrails**, C99**, Spyse (CertDB)*.
  # Read findomain wiki for details: https://github.com/Findomain/Findomain/blob/master/docs/INSTALLATION.md#access-tokens-configuration
  #export findomain_fb_token="YourAccessToken"
  #export findomain_spyse_token="YourAccessToken"
  export findomain_virustotal_token=$virustotal
  export findomain_securitytrails_token=$securitytrails
  findomain -t $domainName -u findomain-output.txt -q 1>/dev/null

  printf "${green}[+] Subfinder${nc}\n"
  # Subfinder - https://github.com/projectdiscovery/subfinder
  # All api keys are in the $HOME/.config/subfinder/provider-config.yaml file.
  # Sources: alienvault,anubis,commoncrawl,crtsh,dnsdumpster,hackertarget,rapiddns,riddler,sitedossier,threatminer,waybackarchive,reconcloud
  # Sources require API key: bevigil*,binaryedge*,bufferover*,c99*,censys*,certspotter*,chaos*,chinaz*,dnsdb*,fofa*,
  #                                             fullhunt*,github*,intelx*,passivetotal*,quake*,robtex*,securitytrails*,shodan*,threatbook*,
  #                                             virustotal*,whoisxmlapi*,zoomeye*,zoomeyeapi*,dnsrepo*,hunter*
  # Read subfinder wiki for details: https://github.com/projectdiscovery/subfinder#post-installation-instructions
  subfinder -all -d $domainName -o subfinder-output.txt -t 1000 -silent 1>/dev/null

  printf "${green}[+] Amass - passive${nc}\n"
  # Amass - https://github.com/OWASP/Amass
  # All api keys are in the $HOME/.config/amass/config.ini file.
  # Migrated into the local database make the process slow, and I don't find proper way to disable it,
  # there was a flag "-nolocaldb" before, but it is deprecated.
  # unhealthy solution: https://github.com/OWASP/Amass/issues/797
  # Store amass database in ram (/dev/shm) then delete graph database after scan completed. 
  amass enum -config $HOME/.config/amass/config.ini -dir /dev/shm/amass -d $domainName -o amassPassive-output.txt -passive -silent 1>/dev/null\
    && rm -rf /dev/shm/amass/*

  printf "${green}[+] gitlab-subdomains${nc}\n"
  # gitlab-subdomains - https://github.com/gwen001/gitlab-subdomains
  export GITLAB_TOKEN=$gitlab
  gitlab-subdomains -d $domainName | tee gitlab-output.txt 1>/dev/null && rm $domainName.txt

  if [ -n "$sublist" ]; then
    printf "${green}[+] shuffledns${nc}\n"
    # shuffledns - https://github.com/projectdiscovery/shuffledns
    shuffledns -d $domainName -w $sublist -r $dnsResolver -o shuffledns-output.txt -silent 1>/dev/null
  fi

  printf "${green}[+] jldc.me${nc}\n"
  curl --silent --insecure --tcp-fastopen --tcp-nodelay https://jldc.me/anubis/subdomains/$domainName | jq -r '.[]' | tee jldc.me-output.txt 1>/dev/null

  if [ -n "$asn" ]; then
    IFS=','

    for n in $asn
    do
      printf "${green}[+] dnsx on $n${nc}\n"
      echo $n | dnsx -silent -resp-only -ptr -output $n-output.txt 1>/dev/null
    done
  fi

  # Process output files
  fn=$domainName-$(date +%s)
  cat *-output.txt | anew > "$fn.txt" && rm -rf *-output.txt

  if [ "$httpxProbe" ]; then
    printf "${green}[!] Running httpx probe...${nc}\n"
    httpx -r $dnsResolver -o "$fn-httpx.txt" -l "$fn.txt" -silent 1>/dev/null
  fi
  
  wc -l $fn*.txt

  # All Done!
  echo -e "\n\033[1;32mFINISHED!\033[0m\n"

}


if [[ -f "$domainName" ]]; then
  while IFS= read -r line; do
    domainName="$(echo $line | unfurl domain | sed 's/^\*\.//g')"
    printf "${yellow}+++ Scanning: $domainName${nc}\n"
    subDomains
  done < "$domainName"
else
  subDomains
fi
