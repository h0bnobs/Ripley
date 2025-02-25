import ftplib
import os
import subprocess
import time

import requests
from libnmap.parser import NmapParser
from pymetasploit3.msfrpc import MsfRpcClient

from scripts.run_commands import run_command_with_output_after, run_command_live_output, \
    run_command_live_output_with_input, run_command_with_input
from scripts.utils import COLOURS, find_full_filepath, parse_nmap_xml
from subprocess import CompletedProcess, CalledProcessError
from typing import List, Dict, Type
from selenium.common import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium import webdriver


def run_wpscan(target: str) -> str:
    """
    Runs the wpscan tool on the target.
    :param target: The target to run wpscan on.
    :return: The output of the wpscan tool as a string or a CalledProcessError.
    """
    # wpscan works both with https:// at the start of the target and without
    command = f'wpscan --url {target} --random-user-agent'
    print(f'{COLOURS["warn"]} Running wpscan! {COLOURS["end"]}')
    try:
        result = run_command_live_output(command)
        return result
    except Exception as e:
        return f"Wpscan failed!"


def get_metasploit_modules(target: str, pid: int) -> list[dict[str, str]]:

    output_filepath = f'flaskr/static/temp/nmap-{target}.xml'
    msf_password = 'msf'

    def connect_to_msf():
        print("[*] Connecting to Metasploit RPC Server...")
        try:
            client = MsfRpcClient(msf_password, port=55553)
            return client
        except requests.exceptions.ConnectionError as e:
            print(f"[!] Connection error: {e}")
            return None

    def stop_msf_rpc(process):
        print("[*] Stopping Metasploit RPC Server...")
        subprocess.Popen(['kill', str(process)])

    def search_for_modules(client, product, version) -> list[dict[str, str]]:
        search_results = client.modules.search(product)
        return [result for result in search_results if any(isinstance(value, str) and version in value for value in result.values())]

    #check_and_kill_msf_rpc()
    #msf_process = start_msf_rpc()
    #pid = msf_process.pid
    try:
        client = connect_to_msf()
        report = NmapParser.parse_fromfile(output_filepath)
        for host in report.hosts: # report.hosts is a list
            for service in host.services: # host.services is a list
                product = service.banner_dict.get('product')
                version = service.banner_dict.get('version')
                if product and version:
                    return search_for_modules(client, product, version)
    except Exception as e:
        print(e)
        stop_msf_rpc(pid)
    return []


def run_wpscan(target: str) -> str:
    """
    Runs the wpscan tool on the target.
    :param target: The target to run wpscan on.
    :return: The output of the wpscan tool as a string or a CalledProcessError.
    """
    # wpscan works both with https:// at the start of the target and without
    command = f'wpscan --url {target} --random-user-agent'
    print(f'{COLOURS["warn"]} Running wpscan! {COLOURS["end"]}')
    try:
        result = run_command_live_output(command)
        return result
    except Exception as e:
        return f"Wpscan failed!"


def is_target_webpage(target: str) -> bool:
    """
    Basic check to see if the target is a webpage based solely whether one of the ports 80, 443, 8080 or 8443 are open.
    :param target: The target to check.
    :return: True if the target has one of the mentioned ports open, False otherwise.
    """
    print(target)
    open_ports = parse_nmap_xml(f'flaskr/static/temp/nmap-{target}.xml', [80, 443, 8080, 8443])
    #return open_ports in ['80', '443', '8080', '8443']
    return any(port in open_ports for port in ['80', '443', '8080', '8443'])
    # if '80' in open_ports or '443' in open_ports or '8080' in open_ports or '8443' in open_ports:
    #     return True
    # return False


def run_dns_recon(target: str) -> str:
    """
    Runs the dnsrecon tool on the target.
    :param target: The target domain.
    :return: The live output of the dnsrecon tool.
    """
    print(f'{COLOURS["warn"]} Running dnsrecon! {COLOURS["end"]}')
    if target.startswith('www.'):
        return run_command_live_output(f"dnsrecon -d {target.replace('www.', '', 1)}")
    else:
        return run_command_live_output(f'dnsrecon -d {target}')


def run_ftp(target: str) -> bool:
    """
    Tries to connect to the target and login to ftp anonymously.
    :param target: The target FTP server.
    :return: True if anonymous connection was successful, False otherwise.
    """
    # if you want to test, machines are fawn, access and Devel on htb.
    try:
        ftp = ftplib.FTP(timeout=10)
        ftp.connect(target)
        ftp.login('anonymous', '')
        print(f'{COLOURS["star"]} Anonymous FTP login successful!{COLOURS["end"]}')
        ftp.quit()
        return True
    except (ftplib.error_perm, Exception) as e:
        print(f'{COLOURS["warn"]} Anonymous FTP not allowed! {COLOURS["end"]}')
        return False


def run_smbclient(target: str) -> None | str:
    """
    Runs the smbclient tool to list shares on the target.
    :param target: The target to run smbclient on.
    :return:
    """
    # if you want to test this properly: https://app.hackthebox.com/machines/186 - box name is bastion and has open
    # smb shares.
    command = f"smbclient -L {target}"
    try:
        print(f'{COLOURS["warn"]} Smbclient will now attempt to list shares. {COLOURS["end"]}')
        # result = run_command_with_output_after(command)
        result = run_command_with_input(command, '\n')
        if result == '':
            result = "No smb shares found!"
        return result
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while executing '{command}': {e}\nError output: {e.stderr}"
        return error_message


def get_screenshot(target: str) -> str:
    """
    Gets a screenshot of the webpage and stores it in the output directory.
    :param target: The target webpage.
    :return: The full filepath of the screenshot.
    """
    print(f'{COLOURS["warn"]} Getting screenshot! {COLOURS["end"]}')
    os.makedirs("output", exist_ok=True)
    attempts = [
        f'https://{target}',
        f'http://{target}',
        f'http://{target}:80',
    ]
    screenshot_path = ""
    for url in attempts:
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Run in headless mode
            chrome_options.add_argument("--no-sandbox")  # Required for some environments
            chrome_options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
            chromedriver = webdriver.Chrome(options=chrome_options)
            chromedriver.set_window_size(1500, 1080)
            chromedriver.set_page_load_timeout(10)
            chromedriver.get(url)
            time.sleep(1)
            screenshot_path = f'output/{target}.png'
            chromedriver.save_screenshot(screenshot_path)
            break
        except WebDriverException:
            continue
    chromedriver.quit()

    if screenshot_path:
        return find_full_filepath('output', f'{target}.png')
    else:
        raise Exception(f"Could not connect to {target} using any protocol.")


def run_host(target: str) -> str:
    """
    Runs the host command on the target.
    :param target: The target to run host on.
    :return: The output of the host command as a string.
    """
    command = f'host {target}'
    if target.startswith('www.'):
        one = run_command_with_output_after(f'host {target.split("www.")[1]}')
        two = run_command_with_output_after(command)
        return f'{one.stdout}\n{two.stdout}'
    else:
        result = run_command_with_output_after(command)
        # print(result.stdout)
        return result.stdout


def run_nmap(target: str, nmap_settings: dict) -> str:
    """
    Runs the port scanner nmap on the target.
    :param target: The target to run nmap on.
    :param nmap_settings: The nmap settings as a dictionary.
    :return: The output of the nmap tool as a string.
    """
    # spinner = Spinner()
    # spinner.start()
    # spinner.stop()
    def scan(command):
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(result.stdout)
            return result.stdout

    command = parse_nmap_settings(nmap_settings, target)
    output = scan(command)
    return output


def parse_nmap_settings(settings: dict, target: str) -> str:
    """
    Takes the nmap settings and target and produces a valid nmap command based off these
    :param settings: The nmap settings as a string.
    :param target: The target to run nmap on.
    :return: The nmap command as a string.
    """
    ports_to_scan = settings.get("ports_to_scan", "")
    scan_type = settings.get("scan_type", "")
    aggressive_scan = settings.get("aggressive_scan", "").lower() == "true"
    scan_speed = settings.get("scan_speed", "")
    os_detection = settings.get("os_detection", "").lower() == "true"
    ping_hosts = settings.get("ping_hosts", "").lower() == "true"
    ping_method = settings.get("ping_method", "")
    host_timeout = settings.get("host_timeout", "")
    command = "nmap"

    # Track whether a port scan is happening
    port_scan_enabled = False

    # Ports Parsing Logic
    if ports_to_scan:
        ports = [p.strip() for p in ports_to_scan.split(',')]  # Strip spaces
        expanded_ports = []

        for port in ports:
            if '*' in port:  # Ignore '*' at this point, handled separately
                continue
            if '-' in port:  # Handle port ranges
                start_port, end_port = map(int, port.split('-'))
                expanded_ports.extend(range(start_port, end_port + 1))
            else:
                expanded_ports.append(port)

        if '*' in ports:  # If '*' was in input, scan all ports
            command += " -p-"
        else:
            ports_to_scan = ','.join(map(str, expanded_ports))
            command += f" -p {ports_to_scan}"

        port_scan_enabled = True  # Ports are being scanned

    else:
        command += " --top-ports 1000"  # Default to top 1k ports if none specified
        port_scan_enabled = True

    # Scan Type Parsing
    if scan_type == "SYN":
        command += " -sS -sV"
        port_scan_enabled = True
    elif scan_type == "UDP":
        command += " -sU"
        port_scan_enabled = True
    elif scan_type == "TCP":
        command += " -sT -sV"
        port_scan_enabled = True

    # Aggressive Scan
    if aggressive_scan:
        command += " -A"

    # Scan Speed
    if scan_speed:
        command += f" -T{scan_speed}"

    # OS Detection
    if os_detection:
        command += " -O"

    # Ping Methods (Only Add `-sn` if No Port Scan is Enabled)
    if ping_hosts:
        if ping_method == "ICMP":
            command += " -PE"
        elif ping_method == "TCP":
            command += " -PS80,443"  # TCP SYN ping with default ports
        elif ping_method == "ARP":
            command += " -PR"
        else:
            command += " -PE"  # Default to ICMP

        if not port_scan_enabled:
            command += " -sn"  # Skip port scanning **only if no scan types are active**
    else:
        command += " -Pn"  # Skip host discovery

    if host_timeout:
        command += f" --host-timeout {host_timeout}s"

    print(f"Generated Nmap Command: {command}")

    # todo logic here for the output file, eg if the user wants to save the output to a file, then change it from this:
    #   because the file in the form `-oX flaskr/static/temp/nmap-{target}.xml` is used in the is_target_webpage function, so if the user wants to save the output
    #       to a file, then we should copy that custom file to that one^

    command += f" -oX flaskr/static/temp/nmap-{target}.xml"

    command += f" {target}"
    return command


def run_ffuf_subdomain(target: str, wordlist_filepath: str, enable_ffuf: str, delay=0) -> str:
    """
    Runs ffuf to find subdomains. WARNING: remember to remove 'www.' from the target before running this function.
    :param target: The target to run ffuf on.
    :param wordlist_filepath: The path to the wordlist file.
    :param enable_ffuf: A string that is either 'True' or 'False' to enable or disable ffuf.
    :param delay: An optional delay to add between requests.
    :return: The output of the ffuf tool as a string or a CalledProcessError.
    """
    if enable_ffuf == 'True':
        print(f'{COLOURS["warn"]} Attempting to find subdomains for {target}! {COLOURS["end"]}')
        # https://raw.githubusercontent.com/DNSPod/oh-my-free-data/master/src/dnspod-top2000-sub-domains.txt
        # command = f'ffuf -w test_subdomains.txt -u https://FUZZ.{target} -H "Host: FUZZ.{target}" -o output/ffuf_subdomain_enumeration_{target}.txt -p {delay}'
        if not wordlist_filepath:
            # check if wordlist exists already in proj root
            for file in os.listdir():
                if file == 'dnspod-top2000-sub-domains.txt':
                    wordlist_filepath = 'dnspod-top2000-sub-domains.txt'
                    break
            else:
                # get suitable wordlist from git if not found
                url = 'https://raw.githubusercontent.com/DNSPod/oh-my-free-data/master/src/dnspod-top2000-sub-domains.txt'
                t = run_command_with_output_after(f'curl -o dnspod-top2000-sub-domains.txt {url}')
                if t.returncode == 0:
                    wordlist_filepath = 'dnspod-top2000-sub-domains.txt'

        if delay != 0:
            command = (
                f'ffuf -w {wordlist_filepath} '
                f'-u https://FUZZ.{target} '
                f'-H "Host: FUZZ.{target}" '
                f'-o output/ffuf_subdomain_enumeration_{target}.txt '
                f'-p {delay}'
            )
        else:
            command = (
                f'ffuf -w {wordlist_filepath} '
                f'-u https://FUZZ.{target} '
                f'-H "Host: FUZZ.{target}" '
                f'-o output/ffuf_subdomain_enumeration_{target}.txt'
            )
        print(f"using {wordlist_filepath}")
        result = run_command_live_output(command)
        #print(f'{COLOURS["warn"]} End of ffuf webpage enumeration! {COLOURS["end"]}')
        return f"Using wordlist: {wordlist_filepath}:\n\n{result}"
    else:
        return "ffuf not enabled!"


def run_ffuf_webpage(target: str, wordlist_filepath: str, enable_ffuf: str, delay = 0) -> str:
    """
    Runs ffuf to find webpages.
    :param target: The target to run ffuf on.
    :param wordlist_filepath: The path to the wordlist file.
    :param enable_ffuf: A string that is either 'True' or 'False' to enable or disable ffuf.
    :param delay: An optional delay to add between requests.
    :return: The output of the ffuf tool as a string or a CalledProcessError.
    """
    print('############# IN FFUF WEBPAGE METHOD #############')
    if enable_ffuf == 'True':
        print(f'{COLOURS["warn"]} Starting ffuf webpage enumeration! {COLOURS["end"]}')

        if not wordlist_filepath:
            # check if wordlist exists already in proj root
            for file in os.listdir():
                if file == 'Directories_Common.wordlist':
                    wordlist_filepath = 'Directories_Common.wordlist'
                    break
            else:
                # get suitable wordlist from git if not found
                url = 'https://raw.githubusercontent.com/emadshanab/WordLists-20111129/master/Directories_Common.wordlist'
                t = run_command_with_output_after(f'curl -o Directories_Common.wordlist {url}')
                if t.returncode == 0:
                    wordlist_filepath = 'Directories_Common.wordlist'

        if delay != 0:
            command = f'ffuf -w {wordlist_filepath} -u https://{target}/FUZZ -o output/ffuf_webpage_enumeration_{target}.txt -fc 404,500 -p {delay}'
        else:
            command = f'ffuf -w {wordlist_filepath} -u https://{target}/FUZZ -o output/ffuf_webpage_enumeration_{target}.txt -fc 404,500'

        print(f"using {wordlist_filepath}")
        result = run_command_live_output(command)
        print(f'{COLOURS["warn"]} End of ffuf webpage enumeration! {COLOURS["end"]}')
        return f"Using wordlist: {wordlist_filepath}:\n\n{result}"
    else:
        return "ffuf not enabled!"


def get_robots_file(target: str) -> str:
    """
    Gets the robots.txt file from the target website.
    :param target: The target server.
    :return: The content of the robots.txt file or an error message.
    """
    print(f'{COLOURS["warn"]} Getting robots.txt file! {COLOURS["end"]}')
    attempts = [
        f'https://{target}/robots.txt',
        f'http://{target}/robots.txt',
    ]

    if not target.startswith('www.') and is_target_webpage(target):
        attempts.append(f'https://www.{target}/robots.txt')
        attempts.append(f'http://www.{target}/robots.txt')

    for url in attempts:
        r = run_command_with_output_after(f'curl {url}')
        if r.returncode == 0 and ('User-agent' in r.stdout or 'User-Agent' in r.stdout):
            return r.stdout

    return "robots.txt file not found!"