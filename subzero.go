package main

/*

Author: @p00rduck
Date: 2023-05-26
Version: v0.0.2-Beta
Description: Golang implementation of "subzero.sh" bash script.

Usage: go run subzero.go -h

*/

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	domainName string
	orgName    string
	sublist    string
	asn        string
	httpxProbe bool
	setup      bool
)

func main() {

	flag.StringVar(&domainName, "d", "", "Target domain OR list of domains")
	flag.StringVar(&orgName, "o", "", "Target organization name")
	flag.StringVar(&sublist, "w", "", "Custom wordlist for DNS based subdomain Brute-force")
	flag.StringVar(&asn, "a", "", "ASN numbers comma separated")
	flag.BoolVar(&httpxProbe, "httpx", false, "Run httpx probe over found subdomains")
	flag.BoolVar(&setup, "setup", false, "Install necessary tools")
	flag.Usage = usage

	flag.Parse()

	fmt.Printf(`
            _    ______              
           | |  |___  /              
  ___ _   _| |__   / / ___ _ __ ___  
 / __| | | | '_ \ / / / _ \ '__/ _ \ 
 \__ \ |_| | |_) / /_|  __/ | | (_) |
 |___/\__,_|_.__/_____\___|_|  \___/  v0.0.2-Beta

                            @p00rduck
`)

	if len(os.Args) == 1 {
		usage()
		os.Exit(0)
	}

	if setup {
		Setup()
		os.Exit(0)
	}

	if domainName == "" || orgName == "" {
		fmt.Fprintln(os.Stderr, "Error: argument -d AND -o is required")
		os.Exit(1)
	}

	divider := strings.Repeat("-", 30)
	fmt.Printf("\n%s\n", divider)
	fmt.Printf("\033[1;33m[+] Organization:\033[0m %s\n\033[1;33m[+] Domain:\033[0m %s\n\033[1;33m[+] Wordlist:\033[0m %s\n\033[1;33m[+] ASN:\033[0m %s\n", orgName, domainName, sublist, asn)
	fmt.Printf("%s\n", divider)

	// Run subDomains() func
	if fileInfo, err := os.Stat(domainName); err == nil && !fileInfo.IsDir() {
		file, err := os.Open(domainName)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			domain := strings.TrimPrefix(strings.TrimSpace(line), "*.")
			fmt.Printf("\033[1;33m+++ Scanning: \033[0m %s\n", domain)
			subDomains(domain, orgName)
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	} else {
		subDomains(domainName, orgName)
	}

}

func usage() {
	fmt.Println("Usage: go run script.go [OPTIONS]")
	fmt.Println("Options:")
	fmt.Println("  -d DOMAIN [REQUIRED]          Target domain OR list of domains")
	fmt.Println("  -o ORG [REQUIRED]             Target organization name")
	fmt.Println("  -w wordlist                   Custom wordlist for DNS based subdomain Brute-force")
	fmt.Println("  -a ASN                        ASN numbers comma separated")
	fmt.Println("  -httpx                        Run httpx probe over found subdomains")
	fmt.Println("  -setup                        Install necessary tools")
	fmt.Println("  -h                            Print Help")
}

// Setup installs required packages, downloads files, sets Go path variables, and installs Go packages
func Setup() {
	// Install required packages
	packages := []string{"curl", "wget", "jq", "amass", "golang"}
	installPackages(packages)

	// Download resolvers.txt
	resolversURL := "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt"
	resolversFilePath := "/usr/share/wordlists/subzero-resolvers.txt"
	downloadFile(resolversURL, resolversFilePath)

	// Set Go path variables
	setGoPathVariables()

	// Create necessary directories
	createDirectory("$HOME/.local/bin")

	// Download and install Findomain
	findomainURL := "https://github.com/Findomain/Findomain/releases/download/8.2.2/findomain-linux.zip"
	findomainFilePath := "$HOME/.local/bin/findomain"
	downloadAndInstallFindomain(findomainURL, findomainFilePath)

	// Install Go packages
	goPackages := []string{
		"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
		"github.com/gwen001/gitlab-subdomains@latest",
		"github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
	}
	installGoPackages(goPackages)
}

// RunCommand runs the specified command with the provided arguments
func RunCommand(debug bool, name string, args ...string) {
	cmd := exec.Command(name, args...)
	if debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func installPackages(packages []string) {
	args := append([]string{"apt", "install", "-y"}, packages...)
	RunCommand(true, "sudo", args...)
}

func setGoPathVariables() {
	goPathVariables := `
# Go path variables
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH
`
	shellRCFiles := []string{"$HOME/.zshrc", "$HOME/.bashrc"}
	for _, rcFile := range shellRCFiles {
		appendToFile(goPathVariables, rcFile)
	}
}

func installGoPackages(packages []string) {
	args := append([]string{"install", "-v"}, packages...)
	goCmd := exec.Command("go", args...)
	goCmd.Stdout = os.Stdout
	goCmd.Stderr = os.Stderr
	if err := goCmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func downloadFile(url, filePath string) {
	RunCommand(true, "sudo", "wget", url, "-O", filePath)
}

func createDirectory(directoryPath string) {
	RunCommand(true, "mkdir", "-p", directoryPath)
}

func downloadAndInstallFindomain(url, installPath string) {
	RunCommand(true, "wget", url, "-P", "/tmp")
	RunCommand(true, "unzip", "-j", "/tmp/findomain-linux.zip", "findomain", "-d", installPath)
	RunCommand(true, "chmod", "+x", installPath)
}

func appendToFile(content, filePath string) {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err = f.WriteString(content); err != nil {
		log.Fatal(err)
	}
}

func setEnv(key, value string) {
	err := os.Setenv(key, value)
	if err != nil {
		log.Fatal(err)
	}
}

func subDomains(domainName string, orgName string) {

	// API keys
	virustotal := ""
	securitytrails := ""
	gitlab := ""

	// Scrapping chaosDB :TEST-OK:
	fmt.Printf("\033[0;32m[+] chaosDB\033[0m\n")

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	url := fmt.Sprintf("https://chaos-data.projectdiscovery.io/index.json")
	response, err := client.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	// Read the response body
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	var chaosDB string
	for _, item := range strings.Split(string(data), "\n") {
		if strings.Contains(strings.ToLower(item), strings.ToLower(orgName)+".zip") {
			startIndex := strings.LastIndex(item, "/") + 1
			endIndex := strings.LastIndex(item, "\"")
			if startIndex >= endIndex {
				break
			}
			filename := item[startIndex:endIndex]
			chaosDB = filename
		}
	}

	if chaosDB != "" {
		downloadURL := fmt.Sprintf("%s/%s", "https://chaos-data.projectdiscovery.io", chaosDB)

		req, err := http.NewRequest("GET", downloadURL, nil)
		if err != nil {
			log.Fatal(err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("Failed to download chaosDB. Status code: %d", resp.StatusCode)
		}

		err = os.Mkdir("chaos.temp", 0755)
		if err != nil {
			log.Fatal(err)
		}

		zipFile := filepath.Base(chaosDB)
		outFile := filepath.Join("chaos.temp", zipFile)

		out, err := os.Create(outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		zipReader, err := zip.OpenReader(outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer zipReader.Close()

		fmt.Printf("\033[0;32m[!] Other root domains in chaosDB\033[0m\n")
		for _, file := range zipReader.File {
			if file.Name == fmt.Sprintf("%s.txt", domainName) {

				subdomainFile, err := file.Open()
				if err != nil {
					log.Fatal(err)
				}
				defer subdomainFile.Close()

				outputFile, err := os.Create("chaosdb-output.txt")
				if err != nil {
					log.Fatal(err)
				}
				defer outputFile.Close()

				_, err = io.Copy(outputFile, subdomainFile)
				if err != nil {
					log.Fatal(err)
				}

			} else if !strings.Contains(file.Name, domainName) {
				fmt.Printf("... %s\n", strings.TrimSuffix(file.Name, ".txt"))
			}
		}

		err = os.RemoveAll("chaos.temp")
		if err != nil {
			log.Fatal(err)
		}

	} else {
		fmt.Println("... NULL")
	}

	// Running findomain Command :TEST-OK:
	fmt.Printf("\033[0;32m[+] Findomain\033[0m\n")
	setEnv("findomain_virustotal_token", virustotal)
	setEnv("findomain_securitytrails_token", securitytrails)
	RunCommand(false, "findomain", "-t", domainName, "-u", "findomain-output.txt", "-q")

	// Running subfinder Command :TEST-OK:
	fmt.Printf("\033[0;32m[+] Subfinder\033[0m\n")
	RunCommand(false, "subfinder", "-all", "-d", domainName, "-o", "subfinder-output.txt", "-t", "1000", "-silent")

	// Running amass Command :TEST-OK:
	fmt.Printf("\033[0;32m[+] Amass - passive\033[0m\n")
	RunCommand(false, "amass", "enum", "-config", fmt.Sprintf("%s/.config/amass/config.ini", os.Getenv("HOME")), "-dir", "/dev/shm/amass", "-d", domainName, "-o", "amassPassive-output.txt", "-passive", "-silent")

	err = os.RemoveAll("/dev/shm/amass/*")
	if err != nil {
		log.Fatal(err)
	}

	// Running gitlab-subdomains Command :TEST-OK:
	fmt.Printf("\033[0;32m[+] gitlab-subdomains\033[0m\n")
	setEnv("GITLAB_TOKEN", gitlab)
	cmd := exec.Command("gitlab-subdomains", "-d", domainName)
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("gitlab-output.txt", output, 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.Remove(fmt.Sprintf("%s.txt", domainName))
	if err != nil {
		log.Fatal(err)
	}

	// Scrapping jldc.me :TEST-OK:
	fmt.Printf("\033[0;32m[+] jldc.me\033[0m\n")
	url = fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domainName)
	response, err = http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	var jldcdata []string
	err = json.NewDecoder(response.Body).Decode(&jldcdata)
	if err != nil {
		log.Fatal(err)
	}

	writeToFile := func(outputFile string, data []string) error {
		file, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer file.Close()

		for _, domain := range data {
			_, err = file.WriteString(domain + "\n")
			if err != nil {
				return err
			}
		}

		return nil
	}

	err = writeToFile("jldc.me-output.txt", jldcdata)
	if err != nil {
		log.Fatal(err)
	}

	// Running shuffledns Command :TEST-OK:
	if sublist != "" {
		fmt.Printf("\033[0;32m[+] shuffledns\033[0m\n")
		RunCommand(false, "shuffledns", "-d", domainName, "-w", sublist, "-r", "/usr/share/wordlists/subzero-resolvers.txt", "-o", "shuffledns-output.txt", "-silent")
	}

	// Running dnsx Command :TEST-OK:
	if asn != "" {
		asnList := strings.Split(asn, ",")
		for _, n := range asnList {
			fmt.Printf("\033[0;32m[+] dnsx on %s\033[0m\n", n)
			cmd := exec.Command("dnsx", "-silent", "-resp-only", "-ptr", "-output", fmt.Sprintf("%s-output.txt", n))
			cmd.Stdin = strings.NewReader(n)
			err := cmd.Run()
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// Processing output files
	fn := fmt.Sprintf("%s-%d.txt", domainName, time.Now().Unix())
	files, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}
	var outputFiles []string
	for _, file := range files {
		if strings.Contains(file.Name(), "-output.txt") {
			outputFiles = append(outputFiles, file.Name())
		}
	}
	contentSet := make(map[string]struct{})
	for _, file := range outputFiles {
		fileContent, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		lines := strings.Split(string(fileContent), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				contentSet[line] = struct{}{}
			}
		}
		err = os.Remove(file)
		if err != nil {
			log.Fatal(err)
		}
	}
	var content []string
	for line := range contentSet {
		content = append(content, line)
	}
	sort.Strings(content)
	contentStr := strings.Join(content, "\n")
	err = ioutil.WriteFile(fn, []byte(contentStr), 0644)
	if err != nil {
		log.Fatal(err)
	}

	// Count total subdomains found
	files, err = ioutil.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if strings.Contains(file.Name(), fn) {
			cmd := exec.Command("wc", "-l", file.Name())
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	// Running httpx Command :TEST-OK:
	if httpxProbe {
		fmt.Printf("\033[0;32m[!] Running httpx probe...\033[0m\n")
		RunCommand(false, "httpx", "-r", "/usr/share/wordlists/subzero-resolvers.txt", "-o", fmt.Sprintf("%s-httpx.txt", fn), "-l", fn, "-silent")
	}

	// All Done!
	fmt.Printf("\n\033[1;32mFINISHED!\033[0m\n")
}
