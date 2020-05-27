#!/usr/bin/python3
import ssl
import urllib.request
import urllib.response
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from libnmap.parser import NmapParser
import sys

#bobjones@coursesoffire.com
#Usage - nmapttp.py nmapscan.xml
#Requires chromedriver to be in the same folder (or sys path) as the script.
#https://chromedriver.storage.googleapis.com/83.0.4103.39/chromedriver_win32.zip

ssl._create_default_https_context = ssl._create_unverified_context

nmapFile = sys.argv[1]

chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument('--ignore-certificate-errors')
chrome_options.add_argument('--ignore-ssl-errors')

def parse_scan_report(nmapFile):
    targets = []
    nmap_report = NmapParser.parse_fromfile(nmapFile)
    for host in nmap_report.hosts:
        for service in host.services:
            if service.state == 'open':
                if 'https' in service.service:
                    targets.append("https://%s:%s" % (host.address, service.port))
                elif 'http' in service.service:
                    targets.append("http://%s:%s" % (host.address, service.port))
                elif 'HTTP/' in service.servicefp:
                    targets.append("http://%s:%s" % (host.address, service.port))
    return targets


def checkValidHTTP(fullUrl):
    try:
        data1 = urllib.request.urlopen(fullUrl)
        return fullUrl
    except (urllib.error.URLError,ConnectionResetError,Exception):
        fullUrllst = fullUrl.split(":")
        newurlHTTP = "https:" + str(fullUrllst[1]) + ":" + str(fullUrllst[2])
        newurlHTTPS = "http:" + str(fullUrllst[1]) + ":" + str(fullUrllst[2])
        try:
            data1 = urllib.request.urlopen(newurlHTTP)
            return newurlHTTP
        except (urllib.error.URLError, ConnectionResetError, Exception):
            try:
                data1 = urllib.request.urlopen(newurlHTTPS)
                return newurlHTTPS
            except (urllib.error.URLError, ConnectionResetError, Exception):
                return "Fail"

nmapUrls = parse_scan_report(nmapFile)
print (str(len(nmapUrls)) + ' Urls Found in nmap scan, connecting to remote hosts for validation:')
validUrls = []
fo = open("nmapURls.txt", "r+")
for fullUrl in nmapUrls:
    url = checkValidHTTP(fullUrl)
    if url != "Fail":
        url = url.strip()
        driver = webdriver.Chrome(options=chrome_options)
        try:
            driver.get(url)
        except:
            driver.get(url)
        urlsplit = url.replace("/", "_")
        urlsplit = urlsplit.replace(":", "_")
        filename = urlsplit + ".png"
        driver.save_screenshot(filename)
        url = url + "\n"
        fo.write(url)
fo.close()





