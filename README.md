# PDF-Parser-VirusTotal-based
PDF Parser based on VirusTotal API
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Faleff-github%2FPDF-Parser-VirusTotal-Based&count_bg=%23FCC624&title_bg=%233C3C3C&icon=virustotal.svg&icon_color=%23E7E7E7&title=VIEWS&edge_flat=false)](https://hits.seeyoufarm.com)

## Licence
![Licence](https://img.shields.io/badge/Licence-GNU3-%239e264c?style=for-the-badge) 

## Components
![Firefox](https://img.shields.io/badge/VirusTotal-062b79?style=for-the-badge&logo=VirusTotal)

## Language Used
![NodeJS](https://img.shields.io/badge/Python-FCC624?style=for-the-badge&logo=Python&logoColor)

## OS Tested
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

## OS UnTested
![Mac OS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0) ![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

## Terminal helper
![](docs/script%20helper.png)

## Example
![](docs/terminal.png)

## Log file example
![](docs/log%20file.png)


## How to use

If you want to try this tool you can use a [malicious file](docs/malicious.pdf) in docs created with metasploit.

[![YouTube Video](docs/img.png)](https://youtu.be/qY1oc1xyU5A)

Use the command -h or --help for receive the following output...

```
-p		PDF file path to analyze
    or --path

-A		Set your VirusTotal API Key
    or --API-Key

-gA		Print your VirusTotal API Key
    or --Get-API-Key

-v		Use this argoument for view a lot more information
    or --verbose

-l		Save in a log file all verbose information
    or --log


Examples:

Set your API:
$ sudo python3 script.py -A <VirusTotal_API_Key>

See your API:
$ sudo python3 script.py -gA

Scan a pdf:
$ sudo python3 script.py -p malicious.pdf

Verbose output:
$ sudo python3 script.py -p malicious.pdf --verbose

Save a in a log file:
$ sudo python3 script.py -p malicious.pdf --log
```

## Argouments

|Argoument|Required|Format|
|--|--|--|
|--path|yes|-p /home/aleff/Documents/malicious.pdf|
||or ->|-p malicious.pdf|
|--API-Key|yes|-A|
|--verbose|no|-v|
|--log|no|-l|
|--Get-API-Key|no|-gA|

## VirusTotal API

Signup to [VirusTotal Website](https://www.virustotal.com/gui/join-us) and go to Account -> API Key

## FAQs

### Why?
- Developed for Network Security course of UNICAL Univeristy
