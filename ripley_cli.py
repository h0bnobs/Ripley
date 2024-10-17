import argparse
import os
from typing import List, Dict
import pexpect
import re
from termcolor import colored
from scripts.run_commands import *
from scripts.utils import COLOURS, Spinner, cli_banner, parse_config_file


def parse_args():
    parser = argparse.ArgumentParser(description="ripley - One stop basic web app scanner.")
    parser.add_argument("-c", "--config", dest="config", required=False, help="Config text file")
    return parser.parse_args()


def main():
    # Average time for threading: 12.62 seconds
    # Average time for multiprocessing: 11.63 seconds
    # Average time for xargs: 13.64 seconds
    cli_banner()
    args = parse_args()
    config = parse_config_file(args.config)

    if not args.config:
        raise Exception("You must use -c to specify a configuration file!")

    # process the configuration settings
    if config is None:
        raise Exception("Config is null!")

    single_target = config.get("single_target", "").strip()
    multiple_targets = config.get("multiple_targets", [])
    targets_file = config.get("targets_file", "").strip()

    target_count = sum([bool(single_target), bool(multiple_targets), bool(targets_file)])

    if target_count != 1:
        raise Exception("You must specify exactly one of 'single_target', 'multiple_targets', or 'targets_file'.")

    target_list = get_target_list(single_target, multiple_targets, targets_file)

    # once target_list is filled, either run_on_multiple_targets or run_on_single_target is called based on the length
    if len(target_list) > 1:
        run_on_multiple_targets(target_list, config)
    elif len(target_list) == 1:
        run_on_single_target(target_list, config)
    else:
        raise Exception("Target list empty!")


def get_target_list(single_target: str, multiple_targets: str, targets_file: str) -> List[str]:
    """
    Returns the list of targets found in the config file. If multiple_targets or targets_file are used then it is a normal list, if single_target is used, then it is a list with 1 element only.
    :param single_target: The value of the single_target setting in the config file.
    :param multiple_targets: The value of the multiple_targets setting in the config file.
    :param targets_file: The value of the targets_file setting in the config file.
    :return: A list of targets found in from the config file.
    """
    target_list = []
    args = parse_args()
    # get targets based on the specified setting
    if single_target:
        print(f"#Debug: Using {single_target} as a target from 'single_target' in {args.config}")
        target_list.append(single_target)
    elif multiple_targets:
        print(f"#Debug: Using {multiple_targets} as targets from 'multiple_targets' in {args.config}")
        target_list.extend(multiple_targets)
    elif targets_file:
        with open(targets_file, "r") as file:
            target_list = [line.strip() for line in file if line.strip()]
        print(f"#Debug: Using {target_list} as targets from 'targets_file' called {targets_file} in {args.config}")
    return target_list


def run_on_multiple_targets(target_list: List[str], config: Dict[str, str]) -> None:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: None
    """
    for target in target_list:
        run_host(f"host {target}")
        nmap_flags = config['nmap_parameters']
        run_nmap(target, nmap_flags)
        run_http_get(target)
        run_smbclient(target)
        run_nikto(target)
        # run_showmount(target)


def run_on_single_target(target_list: List[str], config: Dict[str, str]):
    """
    Runs the tool on one target given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return:
    """
    target = target_list[0]  # assuming there is only one target in the list!
    nmap_flags = config['nmap_parameters']
    # todo do something with this:!!
    output_filename = f"{target}.xml"
    run_host(f"host {target}")
    run_nmap(target, nmap_flags)
    run_http_get(target)
    run_smbclient(target)

    run_nikto(target)
    # host_out = run_host(f"host {target}")
    # run_nmap(target, nmap_flags)
    # httpget_out = run_http_get(target)

    # run_smbclient(target)
    # run_wpscan(target)
    #
    # # showmount_command = "showmount -e "
    # # not working run_showmount(showmount_command)
    #
    # # also not working
    # # run_shc(target)
    #
    # ftp_command = "ftp " + target
    # run_ftp(ftp_command, target)
    #



def run_nmap(target, flags):
    try:
        command = f"nmap {flags} {target}"
        # print(command)
        spinner = Spinner()
        spinner.start()
        result = run_command_with_output_after(command)
        spinner.stop()
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while executing '{command}': {e}\nError output: {e.stderr}"
        return error_message


def run_ftp(command, target_ip):
    # this does not work.....
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
        print(f'{COLOURS["warn"]} Smbclient will now attempt to list shares. {COLOURS["end"]}')
        result = run_command_with_output_after(command)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while executing '{command}': {e}\nError output: {e.stderr}"
        return error_message


def run_http_get(target):
    print(COLOURS["warn"] + " http-get will start now" + COLOURS["end"])
    file_name = "./scripts/http_get_targets.txt"
    final = f"python scripts/http-get-improved.py -i scripts/http_get_targets.txt"
    if os.path.exists(file_name):
        with open(file_name, 'w') as file:
            file.write(f"{target}:80")
    else:
        with open(file_name, 'w') as file:
            file.write(f"{target}:80")
    result = run_command_live_output_with_input(final, f"scripts/http_get_out", 1)
    return result


def run_nikto(target):
    command = f"nikto {target}"
    try:
        print(f'{COLOURS["warn"]} Nikto will now attempt to list shares. {COLOURS["end"]}')
        result = run_command_with_output_after(command)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while executing '{command}': {e}\nError output: {e.stderr}"
        return error_message


def run_showmount(target):
    try:
        command = f"showmount -e {target}"
        print(f"{COLOURS['warn']} showmount will now attempt to query the mount daemon on {target}{COLOURS['end']}")
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(e.stderr)


def run_wpscan(target):
    command = f'wpscan {target} --random-user-agent'
    print(COLOURS["warn"] + " wpscan will now attempt to scan the remote host: " + target + COLOURS["end"])
    try:
        result = run_command_with_output_after(command)
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while executing '{command}': {e}\nError output: {e.stderr}"
        return error_message


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


if __name__ == "__main__":
    main()
