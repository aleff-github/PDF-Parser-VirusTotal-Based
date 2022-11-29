import sys
import requests
import base64
import json
import os   
try:
    from prettytable import PrettyTable
except:
    res = input("You haven't 'prettytable' library, do you want to install it? [yes][nope] default [yes]")
    if res == "" or res == "yes":
        os.system("pip install prettytable")
    else:
        exit()
import sys
try:
    from termcolor import colored
except:
    res = input("You haven't 'termcolor' library, do you want to install it? [yes][nope] default [yes]")
    if res == "" or res == "yes":
        os.system("pip install termcolor")
    else:
        exit()

import platform
import getpass


log_output = ""

def argv_error():
    print("\n-p\t\tPDF file path to analyze\n    or --path\n")
    print("-A\t\tSet your VirusTotal API Key\n    or --API-Key\n")
    print("-gA\t\tPrint your VirusTotal API Key\n    or --Get-API-Key\n")
    print("-v\t\tUse this argoument for view a lot more information\n    or --verbose\n")
    print("-l\t\tSave in a log file all verbose information\n    or --log\n")
    print("\nExamples:")
    print("\nSet your API:\n$ sudo python3 script.py -A <VirusTotal_API_Key>")
    print("\nSee your API:\n$ sudo python3 script.py -gA")
    print("\nScan a pdf:\n$ sudo python3 script.py -p malicious.pdf")
    print("\nVerbose output:\n$ sudo python3 script.py -p malicious.pdf --verbose")
    print("\nSave a in a log file:\n$ sudo python3 script.py -p malicious.pdf --log")

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
def response_parser(response: str, verbose: bool, File_Path: str):
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

    if malicious > 1:
        res = input("Do you want to remove the file? [yes][no] default:[yes]")
        if res == "" or res == "yes":
            if platform.system() == "Linux":
                    os.system(f"sudo rm {File_Path}")
            if platform.system() == "Windows":
                    os.system(f"rm {File_Path}")

def create_config_file(VirusTotal_API_Key: str) -> None:
    if check_sudo_permissions():
        if platform.system() == "Linux":
            os.system(f"sudo echo '{VirusTotal_API_Key}' > ~/.config/VirusTotal_API")
            print(f"{os.popen('cat ~/.config/VirusTotal_API').read()[:5]}***", end="")
        elif platform.system() == "Windows":
            print("Not yet")
        else:
            print("Not yet")

def get_virustotal_api_key() -> str:
    if check_sudo_permissions():
        if platform.system() == "Linux":
            return os.popen('cat ~/.config/VirusTotal_API').read().strip()
        elif platform.system() == "Windows":
            print("Not yet")
            return "-1"
        else:
            print("Not yet")
            return "-1"

def check_sudo_permissions() -> bool:
    if os.geteuid() == 0:
        return True
    else:
        print("You must run the script with sudo or with elevated permissions.", end="")
        exit()

if __name__ == "__main__":

    File_Path = ""
    VirusTotal_API_Key = ""
    verbose = False
    log = False
    
    for i in range(1, len(sys.argv)):
        if((sys.argv[i] == "-p" or sys.argv[i] == "--path") and (len(sys.argv) > i+1)):
            File_Path = sys.argv[i+1]
        elif((sys.argv[i] == "-A" or sys.argv[i] == "--API-Key")):
            if len(sys.argv) != 2:
                print("For save the API Key run just:\tsudo python3 PDF_Parser.py -A or --API-Key")
                exit()
            else:
                if check_sudo_permissions():
                    VirusTotal_API_Key = getpass.getpass("Your Secret API Key: ")
        elif((sys.argv[i] == "-gA" or sys.argv[i] == "--Get-API-Key")):
            print(get_virustotal_api_key().strip(), end="")
        elif((sys.argv[i] == "-v" or sys.argv[i] == "--verbose")):
            verbose = True
        elif((sys.argv[i] == "-l" or sys.argv[i] == "--log")):
            log = True
        elif((sys.argv[i] == "-h" or sys.argv[i] == "--help")):
            argv_error()
            exit()
    
    if VirusTotal_API_Key != "":
        create_config_file(VirusTotal_API_Key)
    else:
        VirusTotal_API_Key = get_virustotal_api_key()
        if VirusTotal_API_Key == "-1": exit()

    if File_Path != "":
        init_print = f"Your File: {File_Path}\nYour API: {VirusTotal_API_Key[:5]}***"
        if verbose:
            print(init_print)
        if log:
            log_output += "\n"+init_print
    else:
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

    response_parser(VirusTotal_response, verbose, File_Path)
    
    if log:
        f = open("PDF_Parser.log", "w")
        f.write(log_output)
        f.close()