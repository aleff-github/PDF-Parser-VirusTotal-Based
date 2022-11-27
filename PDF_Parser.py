import sys
import requests
import base64
import json
from prettytable import PrettyTable
import sys
from termcolor import colored
import os


log_output = ""

def argv_error():
    print("./script [option] [value] ...")
    print("-p\t\tUse this argoument for set your PDF path\n    or --path\n")
    print("-A\t\tUse this argoument for set your VirusTotal API Key\n    or --API-Key\n")
    print("-v\t\tUse this argoument for view a lot more information\n    or --verbose\n")
    print("-l\t\tUse this argoument for save in a log file all verbose information\n    or --log\n")
    print("Examples:")
    print("$ python3 script.py -p <PDF_DOCUMENT_PATH> -A <VirusTotal_API_Key>")
    print("\tGeneric example")
    print("$ python3 script.py -p malicious.pdf -A abcdefg123456789876543234567899876543456789876543456789876543 --verbose")
    print("\tIt will print everything in output")
    print("$ python3 script.py -p malicious.pdf -A abcdefg123456789876543234567899876543456789876543456789876543 --log")
    print("\tIt will print everything in a log file in the same directory where is the script PDF_Parser.py")

def generic_error(error: str) -> None:
    print("\nSomething went wrong... check your private key and your pdf path :-/")
    print(f"\n{error}")

"""
{
    "data": {
        "type": "analysis",
        "id": "<base64_file_id>"
    }
}
"""
def upload_file(File_Path: str, VirusTotal_API_Key: str, verbose: bool) -> str:

    url = "https://www.virustotal.com/api/v3/files"

    files = {"file": (File_Path, open(File_Path, "rb"), "application/pdf")}
    headers = {
        "accept": "application/json",
        "x-apikey": VirusTotal_API_Key
    }

    response = requests.post(url, files=files, headers=headers)

    if response.status_code == 200:
        global log_output
        if verbose:
            print(response.text)
        if log_output != "":
            log_output += "\n"+response.text

        return response.text
    else:
        generic_error(f"[*] Error occurred in upload_file function.\nError code: {response.status_code}")
        return "-1"

"""
Load json response as a dict
"""
def json_load(json_in_string: str):
    return json.loads(json_in_string)      

"""
Get data -> id from VirusTotal response
"""
def get_base64_file_id_from_response(response: str) -> str:
    response_in_dict = json_load(response)
    return response_in_dict["data"]["id"]

"""
Decrypt from base64
"""
def decrypt_from_base64(encrypted_string: str) -> str:
    return base64.b64decode(encrypted_string).decode('ascii')


"""
For check the file you must pass as parameters:
    - MD5 of a file uploaded
    - Your VirusTotal private Key
"""
def check_file(FileMD5: str, VirusTotal_API_Key: str) -> str:

    url = f"https://www.virustotal.com/api/v3/files/{FileMD5}"

    headers = {
        "accept": "application/json",
        "x-apikey": VirusTotal_API_Key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.text
    else:
        generic_error(f"[*] Error occurred in check_file function.\nError code: {response.status_code}")
        return "-1"

"""
Parserize the response
"""
def response_parser(response: str, verbose: bool):
    response_in_dict = json_load(response)
    antivirus_supported = response_in_dict["data"]["attributes"]["last_analysis_results"]
    
    malicious = 0
    global log_output
    
    
    cve = {}
    for antivirus in antivirus_supported:
        if response_in_dict["data"]["attributes"]["last_analysis_results"][f"{antivirus}"]["category"] == "malicious":
            malicious += 1
            cve[f"{antivirus}"] = response_in_dict["data"]["attributes"]["last_analysis_results"][f"{antivirus}"]["result"]

    table = ["Result", "CVE"]
    tab = PrettyTable(table)

    for antivirus in cve.keys():
        tab.add_row([f"{antivirus}", f"{cve[antivirus]}"])
    
    if verbose:
        print(tab)

    if log_output != "":
        log_output += "\n"+str(tab)
    
    else:
        for antivirus in antivirus_supported:
            if response_in_dict["data"]["attributes"]["last_analysis_results"][f"{antivirus}"]["category"] == "malicious":
                malicious += 1

    print_string = ""
    color = ""
    if malicious > 2:
        print_string = 'This document is most likely malicious!!!'
        color = "red"
    elif malicious == 1:
        print_string = "A malicious control has been detected but it could be a false positive."
        color = "yellow"
    else:
        print_string = "This file is safe. :-)"
        color = "yellow"
    
    print(colored(f'\n{print_string}', color, attrs=['reverse', 'blink']))

    if log_output != "":
            log_output += "\n"+print_string

if __name__ == "__main__":

    File_Path = ""
    VirusTotal_API_Key = ""
    verbose = False
    log = False
    
    for i in range(1, len(sys.argv)):
        if((sys.argv[i] == "-p" or sys.argv[i] == "--path") and (len(sys.argv) > i+1)):
            File_Path = sys.argv[i+1]
        elif((sys.argv[i] == "-A" or sys.argv[i] == "--API-Key") and (len(sys.argv) > i+1)):
            VirusTotal_API_Key = sys.argv[i+1]
        elif((sys.argv[i] == "-v" or sys.argv[i] == "--verbose")):
            verbose = True
        elif((sys.argv[i] == "-l" or sys.argv[i] == "--log")):
            log = True
        elif((sys.argv[i] == "-h" or sys.argv[i] == "--help")):
            argv_error()
            exit()

    if File_Path != "" and VirusTotal_API_Key != "":
        init_print = f"Your File: {File_Path}\nYour API: {VirusTotal_API_Key[:5]}***"
        if verbose:
            print(init_print)
        if log:
            log_output += "\n"+init_print
    else:
        argv_error()
        exit()

    response = upload_file(File_Path, VirusTotal_API_Key, verbose)
    
    if response == "-1":
        exit()

    encrypted_FileMD5 = get_base64_file_id_from_response(response)
    
    plaintext_FileMD5 = decrypt_from_base64(encrypted_FileMD5)

    FileMD5 = plaintext_FileMD5.split(":")[0]
    MD5_print = f"MD5: {FileMD5}"
    if verbose:
        print(MD5_print)
    if log:
        log_output += "\n"+MD5_print
    
    VirusTotal_response = check_file(FileMD5, VirusTotal_API_Key)
    
    if VirusTotal_response == "-1":
        exit()

    response_parser(VirusTotal_response, verbose)
    
    f = open("PDF_Parser.log", "w")
    f.write(log_output)
    f.close()