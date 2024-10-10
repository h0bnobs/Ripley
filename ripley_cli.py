import subprocess
import argparse
import os
import xml.etree.ElementTree as ET
import pexpect
import re
from termcolor import colored
from scripts.run_commands import run_verbose_command_with_input, run_verbose_command
from scripts.utils import COLOURS, Spinner, banner, read_config_file


def parse_args():
    parser = argparse.ArgumentParser(description="ripley - One stop basic web app scanner.")
    parser.add_argument("-c", "--config", dest="config", required=False, help="Config text file")
    return parser.parse_args()

def main():
    # Average time for threading: 12.62 seconds
    # Average time for multiprocessing: 11.63 seconds
    # Average time for xargs: 13.64 seconds
    banner()
    args = parse_args()

    if not args.config:
        raise Exception("You must use -c to specify a configuration file!")

    # If -c is provided, process the targets from the config file.
    config = read_config_file(args.config)
    if config is None:
        raise Exception("Config is null!")
    else:
        if len(config.get("targets")) > 1:
            multiple_targets(config)
        elif len(config.get("targets")) == 1:
            single_target(config)
        else:
            raise Exception("No target(s) found!")
    print()


def multiple_targets(config):
    for target in config.get("targets"):
            run_host(f"host {target}")
            nmap_flags = config['nmap_parameters']
            run_nmap(target, nmap_flags)
            run_smbclient(target)
            # run_showmount(target)

def single_target(config):
    target = config.get("target")
    nmap_flags = config['nmap_parameters']
    output_filename = f"{target}.xml"
    run_host(f"host {target}")
    nmap_flags = config['nmap_parameters']

    run_nmap(target, nmap_flags)
    run_http_get()

    smb_client_command = "smbclient -L "
    run_smbclient(smb_client_command)

    wpscan_command = "wpscan --url "
    run_wpscan(wpscan_command)

    # showmount_command = "showmount -e "
    # not working run_showmount(showmount_command)

    # also not working
    # run_shc(target)

    ssl_scan_command = "sslscan --url "
    run_sslscan(ssl_scan_command)

    ftp_command = "ftp " + target
    run_ftp(ftp_command, target)

    nikto_command = "nikto -host " + target
    print(nikto_command)
    run_nikto(nikto_command)


def run_nmap(target, flags):
    try:
        command = f"nmap {flags} {target}"
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


def get_ipv4_addresses(domain):
    # Run the dig command
    result = subprocess.run(['dig', domain, 'A', '+short'], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')

    # Define a regex pattern for IPv4 addresses
    ipv4_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    # Extract and filter IPv4 addresses
    ipv4_addresses = [line for line in output.split('\n') if ipv4_pattern.match(line)]
    return ipv4_addresses


def run_smbclient(target):
    # if you want to test this properly: https://app.hackthebox.com/machines/186 - box name is bastion and has open
    # smb shares.

        command = f"smbclient -L {target}"
        try:
            print(f'\n {COLOURS["warn"]} smbclient will now attempt to anonymously list shares {COLOURS["end"]}')
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, input='\n')
            print(COLOURS["plus"] + " smbclient found some shares! " + COLOURS["end"])
            print(result.stdout)

        except subprocess.CalledProcessError as e:
            print(e.stderr)


def run_http_get():
    target_url = parse_args().target
    print(COLOURS["warn"] + " http-get will start now" + COLOURS["end"])
    file_name = "./scripts/http_get_targets.txt"
    final = f"python scripts/http-get-improved.py -i scripts/http_get_targets.txt"
    if os.path.exists(file_name):
        with open(file_name, 'w') as file:
            file.write(f"{target_url}:80")
    else:
        with open(file_name, 'w') as file:
            file.write(f"{target_url}:80")
    # todo maybe the input to this command ("scripts/http_get_out"), will change later. Maybe have a dir dedicated to entire ripley.cli scan outputs?
    run_verbose_command_with_input(final, f"scripts/http_get_out", 1)


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


def run_showmount(target):
    try:
        command = f"showmount -e {target}"
        print(f"{COLOURS['warn']} showmount will now attempt to query the mount daemon on {target}{COLOURS['end']}")
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
    command = f"python ./scripts/security-header-checker.py -u https://{target_url}"
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


def nmap_command_logic(flags, target):
    """
    Takes the given flags and the target and does the logic for the nmap flags and then runs the command after it has correctly identified the flags.
    :param flags: The Nmap flags given once the program has started running.
    :param target: The current target.
    """
    # this part is logic for the nmap flags
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


if __name__ == "__main__":
    main()
