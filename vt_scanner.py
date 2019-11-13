import requests
import json

myapi_key = "api key here"
myurl = "url here"
file_hash = "275a021bd1663fc695ec2fe2a2c4538aabf651fd0f887654321" # sameple malicious hash


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
    files = {'file': (file_to_scan, open(file_to_scan, 'rb'))}
    response = requests.post(vt_url, files=files, params=params)
    response = response.json()
    print("View scan at " + response['permalink'])
    print(response['verbose_msg'] + ".")
