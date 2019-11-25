import requests
import json
import hashlib
import sys

myapi_key = "your api key here"
myurl = "8.8.8.8"
file_hash = "275a021bd1663fc695ec2fe2a2c4538aabf651fd0f887654321"
test_hash = "69630e4574ec6798239b091cda43dca0"


# function to manage the command line args.
def cmd_args():
    help = "vt_scanner.py <option>\n\t-h\t Help: shows options\n\t-u\t URL Report: accepts a URL or IP address, returns the report of a previously scanned URL\n\t-s\t URL Scan: accepts a URL or IP address, queues a URL to be scanned\n\t-t\t Hash Report: accepts a file hash (MD5, SHA1, SHA2), returns the report of a previously scanned file\n\t-f\t File Scan: accepts a file path, queues a file to be scanned\n\t-m\t Hash a File: accepts a file path, hashes a file, then returns the hash report"
    if(len(sys.argv) == 1):
        print(help)
        return
    arg = sys.argv[1].lower()
    if(arg == "-h"):
        print(help)
        return
    elif(arg == "-u"):
        url = input("Enter suspicious URL: ")
        url_report(myapi_key, url)
    elif(arg == "-s"):
        url = input("Enter suspicious URL: ")
        url_scan(myapi_key, url)
    elif(arg == "-t"):
        hash = input("Enter file hash: ")
        hash_report(myapi_key, hash)
    elif(arg == "-f"):
        file_scan(myapi_key)
    elif(arg == "-m"):
        generate_hash(myapi_key)
    else:
        print(help)
        return


# function to upload a url and return findings.
def url_report(api_key, url):

    vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource':url}
    response = requests.get(vt_url, params=params)
    response = response.json()
    print("URL Scan...")
    # if url has not been scanned before, ask to scan.
    if(response['response_code'] == 0):
        return url_scan(api_key, url)
    # if url has been scanned before, return findings.
    else:
        print(response['url'] + " scanned on " + response['scan_date'] + ".")
        print("Positives: " + str(response['positives']) + " out of " + str(response['total']))
        if(response['positives'] == 0):
            print("Not malicious.")
        else:
            print("Possibly malicious.")
        print("View scan at " + response['permalink'])

# function to queue url scan.
def url_scan(api_key, url):
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url':url}
    response = requests.post(vt_url, data=params)
    response = response.json()
    print(response['url'] + " has not been scanned before.")
    print(response['verbose_msg'] + ".")
    print("View scan at " + response['permalink'])



# function to upload a file hash and report findings.
def hash_report(api_key, hash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': hash}
    response = requests.get(url, params=params)
    response = response.json()
    print("File Hash Scan...")
    # if file has not been scanned before, ask to scan.
    if(response['response_code'] == 0):
        print("File has not been scanned before.")
        scan = input("Would you like to upload file (y/n): ")
        if(scan.lower() == 'y'):
            return file_scan(api_key, 'n')
        else:
            print("No file to scan.")
    # if file has been scanned before, return findings.
    else:
        print("Scanned on " + response['scan_date'] + ".")
        print("Positives: " + str(response['positives']) + " out of " + str(response['total']))
        if(response['positives'] == 0):
            print("Not malicious.")
        else:
            print("Possibly malicious.")
        print("View scan at " + response['permalink'])

# function to queue file scan.
def file_scan(api_key):
    vt_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    print("File Upload...")
    file_to_scan = input("Enter file path: ")
    try:
        files = {'file': (file_to_scan, open(file_to_scan, 'rb'))}
    except:
        print("Could not find " + file_to_scan)
        return
    response = requests.post(vt_url, files=files, params=params)
    response = response.json()
    print("View scan at " + response['permalink'])
    print(response['verbose_msg'] + ".")

def generate_hash(api_key):
    print("Generating MD5 Hash...")
    hasher = hashlib.md5()
    file_path = input("Enter file path: ")
    try:
        with open (file_path, 'rb') as file:
            file = file.read()
            hasher.update(file)
    except:
        print("Could not find " + file_path)
        return
    hash = hasher.hexdigest()
    return hash_report(api_key, hash)

cmd_args()
