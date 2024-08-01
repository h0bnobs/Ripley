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

COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m"
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
    @BeeSec
    Helping you Bee Secure

usage: Ripley.py -u <url>
"""
    print(banner_text)


def parse_args():
    parser = argparse.ArgumentParser(description="Ripley - One stop basic web app scanner.")
    parser.add_argument("-u", "--url", dest="target", required=True, help="Target url")
    return parser.parse_args()


def run_nmap(command):
    try:
        spinner = Spinner()
        spinner.start()
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        spinner.stop()

        print(f"\nCommand '{command}' executed successfully.")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing '{command}': {e}")
        print("Error output:")
        print(e.stderr)


def run_ftp(command, target_ip):
    # this shit does not work.....
    # if you want to test, machines are fawn and access on htb.
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
        print(COLOURS["warn"] + " Error during FTP command execution: " + COLOURS["end"])
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

    xml_file = 'temp_output.xml'
    tree = ET.parse(xml_file)
    root = tree.getroot()
    ip = None
    for address in root.findall(".//address[@addrtype='ipv4']"):
        ip = address.get('addr')

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


def run_http_get(command):
    target_url = parse_args().target
    file_name = "targets_for_ripley.txt"
    if os.path.exists(file_name):
        with open(file_name, 'w') as file:
            file.write(f"{target_url}:80")
    else:
        with open(file_name, 'w') as file:
            file.write(f"{target_url}:80")
    try:
        #doesnt need to be an input because http-get.py is already taking care of all of that, this just prompts the user.
        print(COLOURS["warn"] + " http-get will start now" + COLOURS["end"])
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing '{command}': {e}")
        print("Error output:")
        print(e.stderr)


def run_nikto(command):
    try:
        print('\n' + COLOURS["warn"] + " nikto now running. This will take a long time." + COLOURS["end"])
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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


if __name__ == "__main__":
    banner()
    while True:
        flags = input(
            "What flags do you want to include in your nmap scan? Please format them as follows in the example: 'sV "
            "Pn sC oX'\n").split()
        break

    target = parse_args().target
    if len(flags) >= 1:
        nmap_command = "nmap -oX temp_output.xml "
        for flag in flags:
            nmap_command += f"-{flag} "
    else:
        nmap_command = "nmap -oX temp_output.xml "

    run_nmap(nmap_command + target)

    http_get_targets = "targets_for_ripley.txt"
    http_get_command = "python http-get-ripley.py -i " + http_get_targets
    run_http_get(http_get_command)

    smb_client_command = "smbclient -L "
    run_smbclient(smb_client_command)
    os.remove('temp_output.xml')

    # probably best not to include this as it does not work.....
    ftp_command = "ftp " + target
    run_ftp(ftp_command, target)

    nikto_command = "nikto -host " + target
    run_nikto(nikto_command)

    # if pn_flag == True:
    #     nmap_command = f"nmap -sV -Pn {parse_args().targeturl}"
    #     run_nmap(nmap_command)
    #     run_http_get("python http-get-ripley.py -i targets_for_ripley.txt")
    # else:
    #     nmap_command = f"nmap -sV {parse_args().targeturl}"
    #     run_nmap(nmap_command)
    #     run_http_get("python http-get-ripley.py -i targets_for_ripley.txt")
