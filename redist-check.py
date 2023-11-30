#!/usr/bin/env python3
from getpass import getpass
import sys
import os
import logging
import xmltodict
from rich.console import Console
from rich.table import Table
from multiprocessing import Process
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import webbrowser
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(add_help=True,
                    formatter_class=RawTextHelpFormatter,
                    description='Usage Examples: \n\n\tpython3 redist-check.py\n\n\tpython3 redist-check.py -x /// This one suppresses PopUp Links\n\n\tpython3 redist-check.py -x -w yourfile.html -o\n\n\tpython3 redist-check.py -oxw yourfile.html\n\n\tpython3 redist-check.py -xw -o /// This one will use output.html by default')

parser.add_argument("-x", action = "store_true", help="Optional - Disable Links Pop-Up")

parser.add_argument("-w", required='-o' in sys.argv, nargs='?', const='output.html', help="Optional - Create WebPage from output.  If no file is specified after '-w', then 'output.html' will be used")

parser.add_argument("-o", action = "store_true", help="Requires '-w' - Open Results in Web Browser")

args = parser.parse_args()

if args.x:
    pass
else:
    webbrowser.open('https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008Vp5CAE', new = 2)
    webbrowser.open('https://live.paloaltonetworks.com/t5/customer-advisories/emergency-update-required-pan-os-root-and-default-certificate/ta-p/564672', new = 2)
if args.w:
    html_file = args.w
    console = Console(record=True)
else:
    console = Console()

supported_versions = ["8.1.21-h1", "8.1.25-h1", "9.0.16-h5", "9.0.17", "9.0.17-h1", "9.0.17-h2", "9.0.17-h3", "9.1.11-h4", "9.1.12-h6", "9.1.13-h4", "9.1.14-h7", "9.1.16-h3", "9.1.17", "10.0.11-h3", "10.0.12-h3", "10.0.8-h10", "10.1.10", "10.1.10-h1", "10.1.10-h2", "10.1.10-h3", "10.1.10-h4", "10.1.11", "10.1.11-h1", "10.1.3-h3", "10.1.5-h3", "10.1.9-h5", "10.1.6-h7", "10.1.8-h6", "10.1.9-h3", "10.2.3-h9", "10.2.4", "10.2.4-h1", "10.2.4-h2", "10.2.4-h3", "10.2.4-h4", "10.2.5", "10.2.6", "10.2.7", "11.0.0-h1", "11.0.1-h2", "11.0.2", "11.0.2-h1", "11.0.2-h2", "11.0.3", "11.1.0", "11.1.0-b3", "11.1.0-b4"]

unfixed_versions = ["8.1.0", "8.1.0-b17", "8.1.0-b28", "8.1.0-b33", "8.1.0-b34", "8.1.0-b41", "8.1.0-b50", "8.1.0-b8", "8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.1.4-h4", "8.1.5", "8.1.5-h1", "8.1.6", "8.1.6-h2", "8.1.6-h3", "8.1.6-h5", "8.1.7", "8.1.8", "8.1.8-h5", "8.1.9", "8.1.9-h4", "8.1.10", "8.1.11", "8.1.12", "8.1.12-h3", "8.1.13", "8.1.13-h1", "8.1.14", "8.1.14-h2", "8.1.15", "8.1.15-h2", "8.1.15-h3", "8.1.15-h5", "8.1.16", "8.1.17", "8.1.18", "8.1.19", "8.1.20", "8.1.20-h1", "8.1.21", "8.1.21-h1", "8.1.22", "8.1.23", "8.1.23-h1", "8.1.24", "8.1.24-h1", "8.1.24-h2", "8.1.25", "9.0.0", "9.0.0-b11", "9.0.0-b22", "9.0.0-b28", "9.0.0-b34", "9.0.0-b39", "9.0.0-b7", "9.0.1", "9.0.2", "9.0.2-h4", "9.0.3", "9.0.3-h2", "9.0.3-h3", "9.0.4", "9.0.5", "9.0.5-h1", "9.0.5-h4", "9.0.6", "9.0.6-h1", "9.0.7", "9.0.8", "9.0.9", "9.0.9-h1", "9.0.9-h2", "9.0.10", "9.0.11", "9.0.12", "9.0.13", "9.0.14", "9.0.14-h3", "9.0.14-h4", "9.0.15", "9.0.16", "9.0.16-h2", "9.0.16-h3", "9.0.16-h4", "9.1.0", "9.1.1", "9.1.2", "9.1.2-h1", "9.1.3", "9.1.3-h1", "9.1.4", "9.1.5", "9.1.6", "9.1.7", "9.1.8", "9.1.9", "9.1.10", "9.1.11", "9.1.11-h2", "9.1.11-h3", "9.1.12", "9.1.12-h3", "9.1.13", "9.1.13-h1", "9.1.13-h3", "9.1.14", "9.1.14-h1", "9.1.14-h4", "9.1.14-h5", "9.1.15", "9.1.15-h1", "9.1.16", "10.0.0", "10.0.0-b61", "10.0.1", "10.0.1-c59", "10.0.1-c70", "10.0.2", "10.0.2-c46", "10.0.3", "10.0.3-c31", "10.0.3-c45", "10.0.4", "10.0.4-h2", "10.0.5", "10.0.6", "10.0.7", "10.0.8", "10.0.8-h4", "10.0.8-h8", "10.0.9", "10.0.9-c46", "10.0.10", "10.0.10-h1", "10.0.11", "10.0.11-h1", "10.0.12", "10.0.12-h1", "10.1.0", "10.1.0-b10", "10.1.0-b17", "10.1.0-b6", "10.1.1", "10.1.2", "10.1.3", "10.1.4", "10.1.4-h3", "10.1.4-h4", "10.1.5", "10.1.5-h1", "10.1.5-h2", "10.1.6", "10.1.6-h3", "10.1.6-h5", "10.1.6-h6", "10.1.7", "10.1.8", "10.1.8-h1", "10.1.8-h2", "10.1.8-h4", "10.1.9", "10.1.9-h1", "10.2.0", "10.2.0-h1", "10.2.1", "10.2.2", "10.2.2-h2", "10.2.3", "10.2.3-h2", "10.2.3-h4", "11.0.0", "11.0.0-b2.dev_e_rel", "11.0.0-b3.dev_e_rel", "11.0.0-b4.dev_e_rel", "11.0.0-b5.dev_e_rel", "11.0.0-c1361", "11.0.1"]

supported_table = Table(title="Devices that do not require attention", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
supported_table.add_column("Device Type", width=16, justify="center")
supported_table.add_column("Device Name", width=15, justify="center")
supported_table.add_column("IP Address", justify="center")
supported_table.add_column("SW Version", justify="center")
supported_table.add_column("Scenario 1", justify="center")
supported_table.add_column("Upgrade to Version", justify="center")
supported_table.add_column("Content Version", justify="center")
supported_table.add_column("Scenario 2", justify="center")
supported_table.add_column("Redist Agent", justify="center")
supported_table.add_column("# of Clients", justify="center")
supported_table.add_column("Redist Client", justify="center")
supported_table.add_column("Agents Present", justify="center")

unsupported_table = Table(title="Devices that require PANOS Upgrades and Content Updates", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
unsupported_table.add_column("Device Type", width=16, justify="center")
unsupported_table.add_column("Device Name", width=15, justify="center")
unsupported_table.add_column("IP Address", justify="center")
unsupported_table.add_column("SW Version", justify="center")
unsupported_table.add_column("Scenario 1", justify="center")
unsupported_table.add_column("Upgrade to Version", justify="center")
unsupported_table.add_column("Content Version", justify="center")
unsupported_table.add_column("Upgrade to Content Version", justify="center")
unsupported_table.add_column("Scenario 2", justify="center")
unsupported_table.add_column("Redist Agent", justify="center")
unsupported_table.add_column("# of Clients", justify="center")
unsupported_table.add_column("Redist Client", justify="center")
unsupported_table.add_column("Agents Present", justify="center")

os_table = Table(title="Devices that just Require PANOS Upgrades", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
os_table.add_column("Device Type", width=16, justify="center")
os_table.add_column("Device Name", width=15, justify="center")
os_table.add_column("IP Address", justify="center")
os_table.add_column("SW Version", justify="center")
os_table.add_column("Scenario 1", justify="center")
os_table.add_column("Upgrade to Version", justify="center")
os_table.add_column("Content Version", justify="center")
os_table.add_column("Scenario 2", justify="center")
os_table.add_column("Redist Agent", justify="center")
os_table.add_column("# of Clients", justify="center")
os_table.add_column("Redist Client", justify="center")
os_table.add_column("Agents Present", justify="center")

content_table = Table(title="Devices that just require Content Updates", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
content_table.add_column("Device Type", width=16, justify="center")
content_table.add_column("Device Name", width=15, justify="center")
content_table.add_column("IP Address", justify="center")
content_table.add_column("SW Version", justify="center")
content_table.add_column("Scenario 1", justify="center")
content_table.add_column("Suggested PANOS Version", justify="center")
content_table.add_column("Content Version", justify="center")
content_table.add_column("Upgrade to Content Version", justify="center")
content_table.add_column("Scenario 2", justify="center")
content_table.add_column("Redist Agent", justify="center")
content_table.add_column("# of Clients", justify="center")
content_table.add_column("Redist Client", justify="center")
content_table.add_column("Agents Present", justify="center")

supported_devices_count=0
os_devices_count=0
content_devices_count=0
unsupported_devices_count=0

def get_devices():
    try:
        if len(sys.argv) == 1:
            filename = input("Enter filename that contains the list of Panorama and PANOS Device IP Addresses: ")
            username = input("Login: ")
            password = getpass()
            with open(filename) as df:
               devices = df.read().splitlines()

        else:
            filename = input("Enter filename that contains the list of Panorama and PANOS Device IP Addresses: ")
            username = input("Login: ")
            password = getpass()
            with open(filename) as df:
               devices = df.read().splitlines()
        return devices, username, password
    except FileNotFoundError:
        print('File Not Found')
        k=input("press Enter to exit")
        raise SystemExit(1)
        # pass

def process_list(ip):
    global supported_devices_count, os_devices_count,content_devices_count, unsupported_devices_count
    skip = False
    redist_agent_response = ''
    sys_info_response = ''
    api_response = ''
    api_key = ''
    supported_version = ''
    supported_content_version = ''
    agent_status = ''
    number_of_clients = ''
    client_status = ''
    agents_present = ''
    try:
        uri = "/api/?type=keygen&user=" + username + "&password=" + password
        full_url = "https://" + ip + uri
        api_response = requests.get(full_url, verify=False, timeout=15)
        result_dict = xmltodict.parse(api_response.text)
        api_key = result_dict['response']['result']['key']
        #logging.debug("API Key: " + api_key)
        uri1 = "/api/?type=op&cmd=<show><system><info></info></system></show>&key=" + api_key
        full_url = "https://" + ip + uri1
        sys_info_response = requests.get(full_url, verify=False)
        dev_name_version = xmltodict.parse(sys_info_response.text)
        model = dev_name_version['response']['result']['system']['model']
        devicename =  dev_name_version['response']['result']['system']['devicename']
        serial = dev_name_version['response']['result']['system']['serial']
        family = dev_name_version['response']['result']['system']['family']
        panos_version = dev_name_version['response']['result']['system']['sw-version']
        recommended_version = ""
        check_version = panos_version[:4]
        if check_version[3] == '.':
            check_version = float(check_version[:3])
        if float(check_version) < 10:
            uri4 = "/api/?type=op&cmd=<show><user><user-id-service><status></status></user-id-service></user></show>&key=" + api_key
            full_url = "https://" + ip + uri4
            userid_service_response = requests.get(full_url, verify=False)
            uri5 = "/api/?type=op&cmd=<show><user><user-id-agent><statistics></statistics></user-id-agent></user></show>&key=" + api_key
            full_url = "https://" + ip + uri5
            userid_client_response = requests.get(full_url, verify=False)
            redist_agent_status = xmltodict.parse(userid_service_response.text)
            redist_client_status = xmltodict.parse(userid_client_response.text)
            if "up" in redist_agent_status['response']['result'].split('\n\t')[1]:
                agent_status = "enabled"
                if int(redist_agent_status['response']['result'].split('\n\t')[7].replace("number of clients:", "")) > 0:
                    number_of_clients = str(int(redist_agent_status['response']['result'].split('\n\t')[7].replace("number of clients:", "")))
            else:
                agent_status = "disabled"
                number_of_clients = "N/A"


            try:
                if redist_client_status['response']['result']['entry']:
                    client_status = "enabled"
                    agents_present = "Yes"
            except TypeError:
                    client_status = "disabled"
                    agents_present = "N/A"

        if float(check_version) >= 10:
            uri2 = "/api/?type=op&cmd=<show><redistribution><service><status/></service></redistribution></show>&key=" + api_key
            full_url = "https://" + ip + uri2
            redist_agent_response = requests.get(full_url, verify=False)
            uri3 = "/api/?type=op&cmd=<show><redistribution><agent><state>all</state></agent></redistribution></show>&key=" + api_key
            full_url = "https://" + ip + uri3
            redist_client_response = requests.get(full_url, verify=False)
            redist_agent_status = xmltodict.parse(redist_agent_response.text)
            redist_client_status = xmltodict.parse(redist_client_response.text)
            if redist_agent_status['response']['result']['entry']['status'] == 'up':
                agent_status = "enabled"
                number_of_clients = redist_agent_status['response']['result']['entry']['total-clients']
            else:
                agent_status = "disabled"
                number_of_clients = "N/A"

            try:
                if redist_client_status['response']['result']['entry']['state']:
                    client_status = "enabled"
                    agents_present = "Yes"
            except TypeError:
                    client_status = "disabled"
                    agents_present = "N/A"

    except IOError:
        logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.")
        skip = True
        pass

    except KeyError:
        logging.error(ip+" Incorrect Username/Password, Command not supported on this platform or API Access is not allowed on this user account.")
        skip = True
        pass

    except AttributeError:
        logging.error("No API key was returned.  Insufficient privileges or incorrect credentials given.")
        skip = True
        pass

    except:
        print(ip, "Had an Issue.  Please Investigate.")
        skip = True
        pass

    if skip == True:
        pass
        skip = False
    else:
        try:
            if dev_name_version['response']['result']['system']['sw-version'] in supported_versions:
                supported_version = "Yes"
            else:
                supported_version = "No"

            print("Completed", dev_name_version['response']['result']['system']['devicename'], "with IP Address:", ip)
            content_version = dev_name_version['response']['result']['system']['app-version']
            if float(content_version.replace("-", ".")) >= 8776.8390:
                supported_content_version = "Yes"
            else:
                supported_content_version = "No"

            if panos_version in unfixed_versions:
                if panos_version  == "8.1.0":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b17":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b28":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b33":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b34":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b41":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b50":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.0-b8":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.1":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.2":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.3":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.4":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.4-h4":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.5":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.5-h1":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.6":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.6-h2":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.6-h3":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.6-h5":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.7":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.8":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.8-h5":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.9":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.9-h4":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.10":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.11":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.12":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.12-h3":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.13":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.13-h1":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.14":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.14-h2":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.15":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.15-h2":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.15-h3":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.15-h5":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.16":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.17":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.18":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.19":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.20":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.20-h1":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.21":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.21-h1":
                    recommended_version = "8.1.21-h2"
                if panos_version  == "8.1.22":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "8.1.23":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "8.1.23-h1":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "8.1.24":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "8.1.24-h1":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "8.1.24-h2":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "8.1.25":
                    recommended_version = "8.1.25-h1"
                if panos_version  == "9.0.0":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.0-b11":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.0-b22":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.0-b28":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.0-b34":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.0-b39":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.0-b7":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.1":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.2":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.2-h4":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.3":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.3-h2":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.3-h3":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.4":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.5":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.5-h1":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.5-h4":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.6":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.6-h1":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.7":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.8":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.9":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.9-h1":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.9-h2":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.10":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.11":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.12":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.13":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.14":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.14-h3":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.14-h4":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.15":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.16":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.16-h2":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.16-h3":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.0.16-h4":
                    recommended_version = "9.0.16-h5"
                if panos_version  == "9.1.0":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.1":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.2":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.2-h1":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.3":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.3-h1":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.4":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.5":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.6":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.7":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.8":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.9":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.10":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.11":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.11-h2":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.11-h3":
                    recommended_version = "9.1.11-h4"
                if panos_version  == "9.1.12":
                    recommended_version = "9.1.12-h6"
                if panos_version  == "9.1.12-h3":
                    recommended_version = "9.1.12-h6"
                if panos_version  == "9.1.13":
                    recommended_version = "9.1.13-h4"
                if panos_version  == "9.1.13-h1":
                    recommended_version = "9.1.13-h4"
                if panos_version  == "9.1.13-h3":
                    recommended_version = "9.1.13-h4"
                if panos_version  == "9.1.14":
                    recommended_version = "9.1.14-h7"
                if panos_version  == "9.1.14-h1":
                    recommended_version = "9.1.14-h7"
                if panos_version  == "9.1.14-h4":
                    recommended_version = "9.1.14-h7"
                if panos_version  == "9.1.14-h5":
                    recommended_version = "9.1.14-h7"
                if panos_version  == "9.1.15":
                    recommended_version = "9.1.16-h3"
                if panos_version  == "9.1.15-h1":
                    recommended_version = "9.1.16-h3"
                if panos_version  == "9.1.16":
                    recommended_version = "9.1.16-h3"
                if panos_version  == "10.0.0":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.0-b61":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.1":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.1-c59":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.1-c70":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.2":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.2-c46":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.3":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.3-c31":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.3-c45":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.4":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.4-h2":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.5":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.6":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.7":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.8":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.8-h4":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.8-h8":
                    recommended_version = "10.0.8-h10"
                if panos_version  == "10.0.9":
                    recommended_version = "10.0.11-h3"
                if panos_version  == "10.0.9-c46":
                    recommended_version = "10.0.11-h3"
                if panos_version  == "10.0.10":
                    recommended_version = "10.0.11-h3"
                if panos_version  == "10.0.10-h1":
                    recommended_version = "10.0.11-h3"
                if panos_version  == "10.0.11":
                    recommended_version = "10.0.11-h3"
                if panos_version  == "10.0.11-h1":
                    recommended_version = "10.0.11-h3"
                if panos_version  == "10.0.12":
                    recommended_version = "10.0.12-h3"
                if panos_version  == "10.0.12-h1":
                    recommended_version = "10.0.12-h3"
                if panos_version  == "10.1.0":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.0-b10":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.0-b17":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.0-b6":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.1":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.2":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.3":
                    recommended_version = "10.1.3-h2"
                if panos_version  == "10.1.4":
                    recommended_version = "10.1.5-h3"
                if panos_version  == "10.1.4-h3":
                    recommended_version = "10.1.5-h3"
                if panos_version  == "10.1.4-h4":
                    recommended_version = "10.1.5-h3"
                if panos_version  == "10.1.5":
                    recommended_version = "10.1.5-h3"
                if panos_version  == "10.1.5-h1":
                    recommended_version = "10.1.5-h3"
                if panos_version  == "10.1.5-h2":
                    recommended_version = "10.1.5-h3"
                if panos_version  == "10.1.6":
                    recommended_version = "10.1.6-h7"
                if panos_version  == "10.1.6-h3":
                    recommended_version = "10.1.6-h7"
                if panos_version  == "10.1.6-h5":
                    recommended_version = "10.1.6-h7"
                if panos_version  == "10.1.6-h6":
                    recommended_version = "10.1.6-h7"
                if panos_version  == "10.1.7":
                    recommended_version = "10.1.8-h6"
                if panos_version  == "10.1.8":
                    recommended_version = "10.1.8-h6"
                if panos_version  == "10.1.8-h1":
                    recommended_version = "10.1.8-h6"
                if panos_version  == "10.1.8-h2":
                    recommended_version = "10.1.8-h6"
                if panos_version  == "10.1.8-h4":
                    recommended_version = "10.1.8-h6"
                if panos_version  == "10.1.9":
                    recommended_version = "10.1.9-h3"
                if panos_version  == "10.1.9-h1":
                    recommended_version = "10.1.9-h3"
                if panos_version  == "10.2.0":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.0-h1":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.1":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.2":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.2-h2":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.3":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.3-h2":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "10.2.3-h4":
                    recommended_version = "10.2.3-h9"
                if panos_version  == "11.0.0":
                    recommended_version = "11.0.0-h1"
                if panos_version  == "11.0.0-b2.dev_e_rel":
                    recommended_version = "11.0.0-h1"
                if panos_version  == "11.0.0-b3.dev_e_rel":
                    recommended_version = "11.0.0-h1"
                if panos_version  == "11.0.0-b4.dev_e_rel":
                    recommended_version = "11.0.0-h1"
                if panos_version  == "11.0.0-b5.dev_e_rel":
                    recommended_version = "11.0.0-h1"
                if panos_version  == "11.0.0-c1361":
                    recommended_version = "11.0.0-h1"
                if panos_version  == "11.0.1":
                    recommended_version = "11.0.1-h2"
            else:
                recommended_version = "N/A"

            if float(check_version) < 8.1:
                recommended_version = "8.1.21-h2"

            if supported_version == "Yes" and supported_content_version == "Yes":
                supported_table.add_row(model, devicename, ip, panos_version, 'No', recommended_version, content_version, 'No', agent_status, number_of_clients, client_status, agents_present, style="on green")
                supported_devices_count+=1

            elif supported_version == "No" and supported_content_version == "Yes":
                if agent_status == "disabled" and client_status == "disabled":
                    supported_table.add_row(model, devicename, ip, panos_version, 'No', recommended_version, content_version, 'No', agent_status, number_of_clients, client_status, agents_present, style="on green")
                    supported_devices_count+=1
                else:
                    os_table.add_row(model, devicename, ip, panos_version, 'Yes', recommended_version, content_version, 'No', agent_status, number_of_clients, client_status, agents_present, style="on yellow")
                    os_devices_count+=1

            elif supported_version == "Yes" and supported_content_version == "No":
                content_table.add_row(model, devicename, ip, panos_version, 'No', 'N/A', content_version, '8776-8390 or greater', 'Yes', agent_status, number_of_clients, client_status, agents_present, style="on yellow")
                content_devices_count+=1

            elif supported_version == "No":
                if agent_status == "disabled" and client_status == "disabled":
                    if supported_content_version == "No":
                        content_table.add_row(model, devicename, ip, panos_version, 'No', recommended_version, content_version, '8776-8390 or greater', 'Yes', agent_status, number_of_clients, client_status, agents_present, style="on yellow")
                        content_devices_count+=1

                else:
                    if supported_content_version == "No":
                        unsupported_table.add_row(model, devicename, ip, panos_version, 'Yes', recommended_version, content_version, '8776-8390 or greater', 'Yes', agent_status, number_of_clients, client_status, agents_present, style="white on red")
                        unsupported_devices_count+=1

        except IOError:
            logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.")
            skip = True
            pass

        except KeyError:
            logging.error(ip+" Incorrect Username/Password, Command not supported on this platform or API Access is not allowed on this user account.")
            skip = True
            pass

        except AttributeError:
            logging.error("No API key was returned.  Insufficient privileges or incorrect credentials given.")
            skip = True
            pass

        except:
            print(ip)
            skip = True
            pass

def multi_processing():
    pool = ThreadPool(processes=os.cpu_count())
    res = list(pool.apply_async(process_list, args=(ip,)) for ip in devices)
    pool.close()
    pool.join()
    results = [r.get() for r in res]
devices, username, password = get_devices()
multi_processing()
total_count = unsupported_devices_count+os_devices_count+content_devices_count+supported_devices_count
print("\n\n")
console.print(unsupported_table)
print("\n\n")
console.print(os_table)
print("\n\n")
console.print(content_table)
print("\n\n")
console.print(supported_table)
print("\n\n")
results_table = Table(title="Device Summary", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
results_table.add_column("Status", justify="center")
results_table.add_column("Device Count", justify="center")
results_table.add_row("Number of Devices that require a PANOS upgrade and Content update", str(unsupported_devices_count), style="white on red")
results_table.add_row("Number of Devices that just require a PANOS upgrade", str(os_devices_count), style="on yellow")
results_table.add_row("Number of Devices that just require a Content update", str(content_devices_count), style="on yellow")
results_table.add_row("Number of Devices that do not require attention", str(supported_devices_count), style="on green")
results_table.add_row("Total Devices", str(total_count))
console.print(results_table)

if args.w:
    console.save_html(html_file)
    if args.o:
        webbrowser.open('file://'+os.path.dirname(os.path.realpath(__file__))+'/'+html_file, new = 2)
    else:
        pass

print("\n\n")
k=input("press Enter to exit")
