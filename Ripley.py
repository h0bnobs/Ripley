import subprocess
import argparse
import threading
import itertools
import sys
import time
import os
import xml.etree.ElementTree as ET
import pexpect
import re
from termcolor import colored

COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m",
    "redStart": "\e[31m",
    "redEnd": "\e[0m",
}

SPINNER_STATES = itertools.cycle(['-', '\\', '|', '/'])


class Spinner:
    def __init__(self):
        self.stop_event = threading.Event()
        self.spin_thread = threading.Thread(target=self.spin, daemon=True)

    def spin(self):
        sys.stdout.write(COLOURS["warn"] + " Nmap is now running and may take a while, be patient " + COLOURS["end"])
        while not self.stop_event.is_set():
            sys.stdout.write(next(SPINNER_STATES))
            sys.stdout.flush()
            sys.stdout.write('\b')
            time.sleep(0.1)

    def start(self):
        self.spin_thread.start()

    def stop(self):
        self.stop_event.set()
        self.spin_thread.join()
        sys.stdout.write('\b')


def banner():
    banner_text = r"""
__________.__       .__                
\______   \__|_____ |  |   ____ ___.__.
 |       _/  \____ \|  | _/ __ <   |  |
 |    |   \  |  |_> >  |_\  ___/\___  |
 |____|_  /__|   __/|____/\___  > ____|
        \/   |__|             \/\/     

usage: Ripley.py -u <url>
"""
    print(banner_text)


def parse_args():
    parser = argparse.ArgumentParser(description="Ripley - One stop basic web app scanner.")
    parser.add_argument("-u", "--url", dest="target", required=True, help="Target url")
    return parser.parse_args()


def get_target_ip():
    xml_file = 'temp_output.xml'
    tree = ET.parse(xml_file)
    root = tree.getroot()
    ip = None
    for address in root.findall(".//address[@addrtype='ipv4']"):
        ip = address.get('addr')

    # extra check to make sure the ip is correct
    ips = get_ipv4_addresses(parse_args().target)
    if ip in ips:
        return ip
    else:
        print("Something went wrong getting the target IP")
        return 0


def run_nmap(command):
    try:
        spinner = Spinner()
        spinner.start()
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        spinner.stop()

        print(f"\nCommand '{command}' executed successfully.")
        print(result.stdout)
        print(COLOURS["star"] + COLOURS["star"] + " Target IP is " + str(get_target_ip()) + " " + COLOURS["star"]
              + COLOURS["star"] + "\n")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing '{command}': {e}")
        print("Error output:")
        print(e.stderr)


def run_ftp(command, target_ip):
    # this shit does not work.....
    # if you want to test, machines are fawn, access and Devel on htb.
    try:
        print(COLOURS["warn"] + " attempting to connect to ftp anonymously" + COLOURS["end"])
        child = pexpect.spawn(command)

        child.expect_exact("Connected to " + target_ip + ".")
        child.expect_exact("220 Microsoft FTP Service")

        expect_name = "Name (" + target_ip + ":" + os.getlogin() + "):"
        child.expect_exact(expect_name)
        child.sendline('anonymous')

        child.expect_exact("331 Anonymous access allowed, send identity (e-mail name) as password.")
        child.sendline('')
        response = child.expect_exact("230 User logged in.")

        if response == 0:
            print(COLOURS["plus"] + " ftp login successful!" + COLOURS["end"])
        else:
            print(COLOURS["cross"] + " anonymous login failed." + COLOURS["end"])

    except pexpect.exceptions.ExceptionPexpect as e:
        print(COLOURS["warn"] + " cannot connect to ftp " + COLOURS["end"])
        print(str(e))


# GPT special:
def get_ipv4_addresses(domain):
    # Run the dig command
    result = subprocess.run(['dig', domain, 'A', '+short'], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')

    # Define a regex pattern for IPv4 addresses
    ipv4_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    # Extract and filter IPv4 addresses
    ipv4_addresses = [line for line in output.split('\n') if ipv4_pattern.match(line)]
    return ipv4_addresses


def run_smbclient(command):
    # if you want to test this properly: https://app.hackthebox.com/machines/186 - box name is bastion and has open
    # smb shares.

    ip = get_target_ip()
    # extra check to make sure the ip is correct
    ips = get_ipv4_addresses(parse_args().target)
    if ip in ips:
        command += ip
        try:
            print(COLOURS["warn"] + " smbclient will now attempt to anonymously list shares" + COLOURS["end"])
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, input='\n')
            print(COLOURS["plus"] + " smbclient found some shares! " + COLOURS["end"])
            print(result.stdout)

        except subprocess.CalledProcessError as e:
            print(e.stderr)
    else:
        print(COLOURS["end"] + COLOURS["warn"] + " Something went wrong determining the ip of the target for "
                                                 "smbclient. Have you got the correct target url?" + COLOURS["end"])
        print("IP found during Nmap scan: " + ip)
        print("IP(s) found via dig command:")
        for i in ips:
            print(i)


def run_http_get():
    target_url = parse_args().target
    file_name = "./used_scripts/http_get_targets.txt"
    final = f"python ./used_scripts/http_get_modified.py -i ./used_scripts/http_get_targets.txt"
    if os.path.exists(file_name):
        with open(file_name, 'w') as file:
            file.write(f"{target_url}:80")
    else:
        with open(file_name, 'w') as file:
            file.write(f"{target_url}:80")
    try:
        # doesnt need to be an input because http-get.py is already taking care of all of that, this just prompts the user.
        print(COLOURS["warn"] + " http-get will start now" + COLOURS["end"])
        result = subprocess.run(final, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing '{command}': {e}")
        print("Error output:")
        print(e.stderr)


def run_nikto(n_command):
    try:
        print('\n' + COLOURS["warn"] + " nikto now running. This will take a long time." + COLOURS["end"])
        process = subprocess.Popen(n_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output.strip())

        stderr = process.communicate()[1]
        if process.returncode != 0:
            print(stderr.strip())

    except subprocess.CalledProcessError as e:
        print(e.stderr)


def run_showmount(command):
    try:
        ip = get_target_ip()
        command += ip
        print(COLOURS["warn"] + " showmount will now attempt to query the mount daemon on the remote host: " + ip +
              COLOURS["end"])
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(e.stderr)


def run_wpscan(command):
    target_url = parse_args().target
    final = command + target_url + " --random-user-agent"
    print(COLOURS["warn"] + " wpscan will now attempt to scan the remote host: " + target_url + COLOURS["end"])
    try:
        process = subprocess.Popen(final, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output.strip())

        stderr = process.communicate()[1]
        if process.returncode != 0:
            print(stderr.strip())

    except subprocess.CalledProcessError as e:
        print(e.stderr)


def run_host(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(colored(result.stdout, "red"))
    except subprocess.CalledProcessError as e:
        print(e.stderr)


def run_shc(target_url):
    command = f"python ./used_scripts/security-header-checker.py -u https://{target_url}"
    print(COLOURS["warn"] + " Scanning for security headers and cookie attributes" + COLOURS["end"])
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
        print("\n")
    except subprocess.CalledProcessError as e:
        print(e.stderr)


def run_sslscan(command):
    final = f"{command}{parse_args().target}:443"
    print(COLOURS["warn"] + " sslscan is now running" + COLOURS["end"])
    try:
        result = subprocess.run(final, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(e.stderr)


def main():
    # Average time for threading: 12.62 seconds
    # Average time for multiprocessing: 11.63 seconds
    # Average time for xargs: 13.64 seconds
    banner()
    target = parse_args().target
    run_host(f"host {target}")
    flags = input(
        "Enter the flags you want for your nmap scan (e.g., 'sS O oX <output>'). Type '1' for an aggressive scan: ").split()

    output_file = next((flags[i + 1] for i, flag in enumerate(flags) if flag == "oX"), None)
    aggressive = '1' in flags

    if aggressive is False:
        if output_file is None:
            nmap_command = "nmap -oX temp_output.xml "
            for flag in flags:
                nmap_command += f"-{flag} "
        else:
            nmap_command = f"nmap -oX {output_file} "
            for flag in flags:
                if flag != f"{output_file}" and flag != 'oX':
                    nmap_command += f"-{flag} "

        def is_substring_repeated(main_string, substring):
            return main_string.count(substring) > 1

        if is_substring_repeated(nmap_command.strip(), "oX"):
            print("\nYour flags:")
            for flag in flags:
                print(f"{flag} ")
            raise Exception("Something has gone wrong with your nmap flags, please double check them and try again.")
        run_nmap(f"{nmap_command}{target}".strip())
    elif aggressive is True:
        # TODO: add some kinda warning
        run_nmap(f"nmap -A {target}")

    run_http_get()

    smb_client_command = "smbclient -L "
    run_smbclient(smb_client_command)

    wpscan_command = "wpscan --url "
    run_wpscan(wpscan_command)

    #showmount_command = "showmount -e "
    #not working run_showmount(showmount_command)

    run_shc(target)

    ssl_scan_command = "sslscan --url "
    run_sslscan(ssl_scan_command)

    ftp_command = "ftp " + target
    run_ftp(ftp_command, target)

    nikto_command = "nikto -host " + target
    print(nikto_command)
    run_nikto(nikto_command)

    os.remove('temp_output.xml')


if __name__ == "__main__":
    main()
