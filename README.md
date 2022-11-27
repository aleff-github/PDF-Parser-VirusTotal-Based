# PDF-Parser-VirusTotal-based
PDF Parser based on VirusTotal API

![](docs/log%20file.png)
<center>Log file example</center>


![](docs/terminal%20verbose.png)
<center>Terminal output example</center>


## How to use

Use the command -h or --help for receive the following output...

```
./script [option] [value] ...
-p		Use this argoument for set your PDF path
    or --path

-A		Use this argoument for set your VirusTotal API Key
    or --API-Key

-v		Use this argoument for view a lot more information
    or --verbose

-l		Use this argoument for save in a log file all verbose information
    or --log

Examples:
$ python3 script.py -p <PDF_DOCUMENT_PATH> -A <VirusTotal_API_Key>
	Generic example
$ python3 script.py -p malicious.pdf -A abcdefg123456789876543234567899876543456789876543456789876543 --verbose
	It will print everything in output
$ python3 script.py -p malicious.pdf -A abcdefg123456789876543234567899876543456789876543456789876543 --log
	It will print everything in a log file in the same directory where is the script PDF_Parser.py
```

## Argouments

|Argoument|Required|Format|
|--|--|--|
|--path|yes|--path /home/aleff/Documents/malicious.pdf|
|--API-Key|yes|--API-Key abcdefg123456789876543234567899876...|
|--verbose|no|--verbose|
|--log|no|--log|

## VirusTotal API

Signup to [VirusTotal Website](https://www.virustotal.com/gui/join-us) and go to Account -> API Key

## FAQs

### Why?
- Developed for Network Security course of UNICAL Univeristy
