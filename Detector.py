import json
import re
import requests
from typing import Union

def is_valid_ipv4(ip):
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(ip_pattern, ip) is not None

def is_valid_url(url):
    url_pattern = r"^(https?):\/\/[^\s\/$.?#].[^\s]*$"
    return re.match(url_pattern, url) is not None

def is_valid_domain(domain):
    domain_pattern = r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$"
    return re.match(domain_pattern, domain) is not None

def scan_ip(text):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.findall(ip_pattern, text)
    return None if match == [] else match[0]

def scan_domain(text):
    domain_pattern = r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,6}\b"
    match = re.findall(domain_pattern, text)
    return None if match == [] else match[0]

def is_malware(vttext: dict) -> bool:
    data: dict = vttext['data']['attributes']['last_analysis_stats']
    return True if data['malicious'] != 0 else False
    
def vt_ip(ip):
    finalurl = ''.join([VT_URL_IP, "/", ip])
    requestsession = requests.Session()
    requestsession.headers.update({'x-apikey': VTAPI})
    requestsession.headers.update({'content-type': 'application/json'})
    response = requestsession.get(finalurl)
    vttext = json.loads(response.text)

    if (response.status_code == 200) and is_malware(vttext):
        DataBase.update(ip)
        return True
    return False

def vt_domain(domain):
    finalurl = ''.join([VT_URL_DOMAIN, "/", domain])
    requestsession = requests.Session()
    requestsession.headers.update({'x-apikey': VTAPI})
    requestsession.headers.update({'content-type': 'application/json'})
    response = requestsession.get(finalurl)
    vttext = json.loads(response.text)

    if (response.status_code == 200) and is_malware(vttext):
        DataBase.update(domain, False)
        return True
    return False

def vt_url(myurl):
    finalurl = ''.join([VT_URL_URL, "/", myurl])
    requestsession = requests.Session()
    requestsession.headers.update({'x-apikey': VTAPI})
    requestsession.headers.update({'content-type': 'application/json'})
    response = requestsession.get(finalurl)
    vttext = json.loads(response.text)

    if (response.status_code == 200) and is_malware(vttext):
        DataBase.update(myurl, False)
        return True
    return False


REPORT_PATH = 'reports/report.json'
IP_PATH = 'database/ips.txt'
DOMAIN_PATH = 'database/domains.txt'
COLORS = {
    'red': '\033[31m',
    'blue': '\033[44m',
    'yellow': '\033[93m',
    'green': '\033[32m',
    'reset': '\033[0m'
}

VTAPI = '50a95916b4a61895ca898922330057ed69ca9b63d3d05095b0d906549e6ca55c'
VT_URL_FILE = 'https://www.virustotal.com/api/v3/files'
VT_URL_URL = 'https://www.virustotal.com/api/v3/urls'
VT_URL_IP = 'https://www.virustotal.com/api/v3/ip_addresses'
VT_URL_DOMAIN = 'https://www.virustotal.com/api/v3/domains'

NUMBER_OF_TARGETS = 5

class DataBase:
    __database__: dict[str, list] = None
    def __new__(cls):
        if cls.__database__ is None:
            cls.__database__: dict[str, list] = {
                'IP': open(IP_PATH, 'r').read().split('\n'), 
                'DOMAIN': open(DOMAIN_PATH, 'r').read().split('\n')
            }
        return cls.__database__
    
    @staticmethod
    def close():
        open(IP_PATH, 'w').write('\n'.join(DataBase.__database__.get('IP')))
        open(DOMAIN_PATH, 'w').write('\n'.join(DataBase.__database__.get('DOMAIN')))
    
    @staticmethod
    def ip_cheking(ip):
        if ip in DataBase.__database__['IP']:
            return True
        else:
            return vt_ip(ip)
        
    @staticmethod
    def domain_checking(domain):
        if domain in DataBase.__database__['DOMAIN']:
            return True
        else:
            return vt_domain(domain)
        
    @staticmethod
    def update(data, is_ip = True):
        if is_ip:
            DataBase.__database__['IP'].append(data)
        else:
            DataBase.__database__['DOMAIN'].append(data)

database = DataBase()

class Info:
    HANDLE: int = -1
    READ: bool = False
    WRITE: bool = False

class File(Info):
    def __init__(self, handle) -> None:
        self.HANDLE = handle

class Registry(Info):
    def __init__(self, handle) -> None:
        self.HANDLE = handle

class Detector:
    def __init__(self, records: dict[object, dict] = None) -> None:
        self.records: dict[object, dict] = records if records != None else self.load()
        self.data: list[Info] = []

    def load(self):
        f = open(REPORT_PATH, 'r').read()
        return json.loads(f)

    def analysis(self):
        count_delete_file = 0
        count_move_file = 0
        count_copy_file = 0
        for _, record in self.records.items():
            record_keys = list(record.keys())
            if ('CreateProcess' in record_keys) or ('CreateRemoteThread' in record_keys):
                self.print_suspect()
            elif ('GetAddrInfo' in record_keys) or ('WinHttpGetProxyForUrl' in record_keys):
                ip = record.get('GetAddrInfo')
                url = record.get('WinHttpGetProxyForUrl')

                if ip != None:
                    if is_valid_ipv4(ip):
                        self.print_malware() if DataBase.ip_cheking(ip) else self.print_suspect() 
                    else:
                        self.print_malware() if DataBase.domain_checking(ip) else self.print_suspect() 

                if url != None:
                    ip = scan_ip(url)
                    if ip != None:
                        self.print_malware() if DataBase.ip_cheking(ip) else self.print_suspect()
                    domain = scan_domain(url) 
                    if domain != None:
                        self.print_malware() if DataBase.domain_checking(domain) else self.print_suspect() 
            else:
                if ('CreateFile' in record_keys) or ('OpenFile' in record_keys):
                    self.data.append(File(record['Handle']))
                elif 'ReadFile' in record_keys:
                    self.setRead(record['ReadFile'], True)
                elif 'writeFile' in record_keys:
                    yara_detector = record.get('Yara Detector')
                    if yara_detector != None:
                        self.print_malware()
                    self.setWrite(record['WriteFile'], True)
                elif 'DeleteFile' in record_keys:
                    count_delete_file += 1
                elif 'MoveFile' in record_keys:
                    count_move_file += 1
                elif 'CopyFile' in record_keys:
                    count_copy_file += 1

                if ('RegCreateKey' in record_keys) or ('RegOpenKey' in record_keys):
                    self.data.append(Registry(record['Handle']))
                elif ('RegSetValueEx' in record_keys) or ('RegSetValue' in record_keys):
                    yara_detector = record.get('Yara Detector')
                    if yara_detector != None:
                        self.print_malware()
                    self.setWrite(record['Handle'], True)

        if (count_delete_file >= NUMBER_OF_TARGETS) or (count_move_file >= NUMBER_OF_TARGETS) or (count_copy_file >= NUMBER_OF_TARGETS):
            self.print_malware()
        count_file, count_registry = self.counter()
        if (count_file >= NUMBER_OF_TARGETS) or (count_registry >= NUMBER_OF_TARGETS):
            self.print_malware()
        self.print_safety()

    def setRead(self, handle, is_read):
        for i in range(len(self.data)):
            if handle == self.data[i].HANDLE:
                self.data[i].READ = is_read
                return

    def setWrite(self, handle, is_write):        
        for i in range(len(self.data)):
            if handle == self.data[i].HANDLE:
                self.data[i].WRITE = is_write
                return

    def is_suspect(self, o: Info):
        return True if (Info.HANDLE != -1) and ((Info.READ) or (Info.WRITE)) else False

    def counter(self):
        file, registry = 0, 0
        for o in self.data:
            if isinstance(o, File):
                file += 1 if self.is_suspect(o) else 0
            else:
                registry += 1 if self.is_suspect(o) else 0
        return (file, registry)

    def print_suspect(self):
        print(COLORS['yellow'], 'Suspicious' , COLORS['reset'])
        exit(0)

    def print_safety(self):
        print(COLORS['green'], 'Harmless' , COLORS['reset'])
        exit(0)

    def print_malware(self):
        print(COLORS['red'], 'Malicious', COLORS['reset'])
        exit(0)
