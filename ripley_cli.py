import argparse, subprocess, os, time, ftplib, concurrent.futures, re, concurrent.futures
from argparse import Namespace
from subprocess import CompletedProcess, CalledProcessError
from typing import List, Dict, Type, IO
from selenium.common import WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium import webdriver
from termcolor import colored
from flaskr import get_db
from flask import current_app
from scripts.chatgpt_call import make_chatgpt_api_call
from scripts.run_commands import run_command_with_output_after, run_command_live_output_with_input, \
    run_command_live_output, run_command_no_output
from scripts.utils import COLOURS, Spinner, cli_banner, parse_config_file, find_full_filepath, remove_ansi_escape_codes, \
    parse_nmap_xml, remove_leading_newline


def parse_args() -> Namespace:
    """
    Parses the arguments from the command line.
    :return: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="ripley - One stop basic web app scanner.")
    parser.add_argument("-c", "--config", dest="config", required=False, help="Config text file")
    return parser.parse_args()


def main():
    """
    Function that runs the tool.
    :return:
    """
    from flaskr import create_app
    app = create_app()
    with app.app_context():
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

    def process_target(app, target: str) -> None:
        """
        Processes a single target.
        :param app: The flask app.
        :param target: The target to process.
        :return: The path to the temp file as a string.
        """
        with app.app_context():
            nmap_flags = config['nmap_parameters']
            print(f'{COLOURS["warn"]} Host information about {target}: {COLOURS["end"]}')
            host_output = run_host(target)
            print(f'{COLOURS["warn"]} End of host information about {target}. {COLOURS["end"]}')
            print(f'{COLOURS["warn"]} Nmap results for {target}: {COLOURS["end"]}')
            nmap_output = run_nmap(target, nmap_flags)
            print(f'{COLOURS["warn"]} End of nmap results for {target}. {COLOURS["end"]}')
            print(f'{COLOURS["warn"]} Smbclient info for {target}: {COLOURS["end"]}')
            smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
            print(f'{COLOURS["warn"]} End of smbclient info for {target} {COLOURS["end"]}')
            print(f'{COLOURS["warn"]} Attempting to connect to ftp anonymously on {target}! {COLOURS["end"]}')
            ftp_allowed = run_ftp(target)
            ftp_string = ('Anonymous FTP allowed!', 'light_green') if ftp_allowed else colored(
                'Anonymous FTP login not allowed!', 'red')
            print(ftp_string)
            if is_target_webpage(target):
                print(f'{COLOURS["warn"]} Starting ffuf webpage enumeration! {COLOURS["end"]}')
                ffuf_webpage_output = run_ffuf_webpage(target, delay=0.2)
                print(f'{COLOURS["warn"]} End of ffuf webpage enumeration! {COLOURS["end"]}')
                print(f'{COLOURS["warn"]} Getting robots.txt file for {target}! {COLOURS["end"]}')
                robots_output = get_robots_file(target).stdout
                print(f'{COLOURS["warn"]} End of robots file for {target} {COLOURS["end"]}\n')
                print(f'{COLOURS["warn"]} Attempting to find subdomains for {target}! {COLOURS["end"]}')
                if target.startswith('www.'):
                    ffuf_temp_target = target[4:]
                    ffuf_subdomain_output = run_ffuf_subdomain(ffuf_temp_target)
                else:
                    ffuf_subdomain_output = run_ffuf_subdomain(target)
                print(f'{COLOURS["warn"]} Getting screenshot for {target}! {COLOURS["end"]}')
                screenshot_filepath = get_screenshot(target)
                if screenshot_filepath:
                    os.makedirs('flaskr/static/screenshots', exist_ok=True)
                    run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
                    print(
                        f"{colored('Screenshot acquired and is stored in:', 'green')} {colored(f'flaskr/static/screenshots/{target}.png\n', 'red')}")
            else:
                print(
                    f'{COLOURS["warn"]} Target is not a webpage, skipping screenshot, subdomain/web page enumeration and the robots file! {COLOURS["end"]}')

            print(f'{COLOURS["warn"]} Running dnsrecon on {target}! {COLOURS["end"]}')
            dns_recon_output = run_dns_recon(target)
            print(f'{COLOURS["warn"]} End of dnsrecon sscan on {target}. {COLOURS["end"]}')
            result = {
                'target': target,
                'host_output': host_output,
                'subdomain_enumeration': ffuf_subdomain_output,
                'dns_recon_output': dns_recon_output,
                'nmap_output': nmap_output,
                'smbclient_output': smbclient_output,
                'ftp_result': ftp_string,
                'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
                'robots_file': robots_output
            }
            print(f'{COLOURS["warn"]} AI advice for {target}: {COLOURS["end"]}')
            ai_advice = make_chatgpt_api_call(result)
            print(ai_advice)
            db = get_db()
            db.execute(
                "INSERT INTO scan_results (target, host_output, subdomains_found, webpages_found, dns_recon_output, "
                "nmap_output, smbclient_output, ftp_result, screenshot, robots_output, ai_advice) VALUES (?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?, ?)",
                (target,
                 host_output,
                 remove_leading_newline(remove_ansi_escape_codes(ffuf_subdomain_output)),
                 remove_leading_newline(remove_ansi_escape_codes(ffuf_webpage_output)),
                 dns_recon_output,
                 nmap_output,
                 smbclient_output,
                 ftp_string,
                 screenshot_filepath,
                 robots_output,
                 ai_advice))
            db.commit()

    a = current_app._get_current_object()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_target, a, target): target for target in target_list}


def run_on_single_target(target_list: List[str], config: Dict[str, str]) -> None:
    """
    Runs the tool on one target given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    """
    target = target_list[0]  # assuming there is only one target in the list!
    nmap_flags = config['nmap_parameters']
    host_output = run_host(target)
    nmap_output = run_nmap(target, nmap_flags)
    wpscan_output = run_wpscan(target)
    smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
    print("")
    print(f'{COLOURS["warn"]} Attempting to connect to ftp anonymously! {COLOURS["end"]}')
    ftp_allowed = run_ftp(target)
    ftp_string = ('Anonymous FTP allowed!', 'light_green') if ftp_allowed else colored(
        'Anonymous FTP login not allowed!', 'red')
    print(ftp_string)
    if is_target_webpage(target):
        print(f'{COLOURS["warn"]} Starting ffuf webpage enumeration! {COLOURS["end"]}')
        ffuf_webpage_output = run_ffuf_webpage(target, delay=0.2)
        print(f'{COLOURS["warn"]} End of ffuf webpage enumeration! {COLOURS["end"]}')
        print(f'{COLOURS["warn"]} Getting robots.txt file! {COLOURS["end"]}')
        robots_output = get_robots_file(target).stdout
        print(f'{COLOURS["warn"]} End of robots file. {COLOURS["end"]}\n')
        print(f'{COLOURS["warn"]} Attempting to find subdomains for {target}! {COLOURS["end"]}')
        if target.startswith('www.'):
            ffuf_temp_target = target[4:]
            ffuf_subdomain_output = run_ffuf_subdomain(ffuf_temp_target)
        else:
            ffuf_subdomain_output = run_ffuf_subdomain(target)
        print(f'{COLOURS["warn"]} Getting screenshot! {COLOURS["end"]}')
        screenshot_filepath = get_screenshot(target)
        if screenshot_filepath:
            os.makedirs('flaskr/static/screenshots', exist_ok=True)
            run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
            print(
                f"{colored('Screenshot acquired and is stored in:', 'green')} {colored(f'flaskr/static/screenshots/{target}.png\n', 'red')}")
    else:
        print(
            f'{COLOURS["warn"]} Target is not a webpage, skipping screenshot, subdomain/web page enumeration and the robots file! {COLOURS["end"]}')
    print(f'{COLOURS["warn"]} Running dnsrecon! {COLOURS["end"]}')
    dns_recon_output = run_dns_recon(target)
    result = {
        'target': target,
        'host_output': host_output,
        'subdomain_enumeration': ffuf_subdomain_output,
        'webpages_found': ffuf_webpage_output,
        'dns_recon_output': dns_recon_output,
        'nmap_output': nmap_output,
        'smbclient_output': smbclient_output,
        'ftp_result': ftp_string,
        'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
        'robots_file': robots_output
    }
    ai_advice = make_chatgpt_api_call(result)
    print(ai_advice)
    db = get_db()
    db.execute(
        "INSERT INTO scan_results (target, host_output, subdomains_found, webpages_found, dns_recon_output, "
        "nmap_output, smbclient_output, ftp_result, screenshot, robots_output, ai_advice) VALUES (?, ?, ?, ?, ?, ?, "
        "?, ?, ?, ?, ?)",
        (target,
         host_output,
         remove_leading_newline(remove_ansi_escape_codes(ffuf_subdomain_output)),
         remove_leading_newline(remove_ansi_escape_codes(ffuf_webpage_output)),
         dns_recon_output,
         nmap_output,
         smbclient_output,
         ftp_string,
         screenshot_filepath,
         robots_output,
         ai_advice))
    db.commit()


def is_target_webpage(target: str) -> bool:
    """
    Basic check to see if the target is a webpage based solely whether one of the ports 80, 443, 8080 or 8443 are open.
    :param target: The target to check.
    :return: True if the target has one of the mentioned ports open, False otherwise.
    """
    open_ports = parse_nmap_xml(f'flaskr/static/temp/nmap-{target}.xml', [80, 443, 8080, 8443])
    run_command_no_output(f'rm flaskr/static/temp/nmap-{target}.xml')
    if '80' in open_ports or '443' in open_ports or '8080' in open_ports or '8443' in open_ports:
        return True
    return False


def run_nmap(target: str, nmap_settings: dict) -> str:
    """
    Runs the nmap tool on the target.
    :param target: The target to run nmap on.
    :return: The output of the nmap tool as a string or a CalledProcessError.
    """
    command = parse_nmap_settings(nmap_settings, target)
    spinner = Spinner()
    spinner.start()
    result = run_command_live_output(command)
    #result = run_command_with_output_after(command)
    spinner.stop()
    return result


def parse_nmap_settings(nmap_settings: dict, target: str) -> str:
    """
    Takes the nmap settings and target and produces a valid nmap command based off these
    :param nmap_settings: The nmap settings as a string.
    :param target: The target to run nmap on.
    :return: The nmap command as a string.
    """
    ports_to_scan = nmap_settings.get("ports_to_scan", "")
    scan_type = nmap_settings.get("scan_type", "")
    aggressive_scan = nmap_settings.get("aggressive_scan", "")
    scan_speed = nmap_settings.get("scan_speed", "")
    os_detection = nmap_settings.get("os_detection", "")
    command = 'nmap'

    # ports parsing logic
    if ports_to_scan:
        ports = ports_to_scan.split(', ')
        if len(ports) == 1:  # if only one value is given
            if ports[0] == '*':  # if all ports
                command += f" -p-"  # scan all ports
            else:
                command += f" -p {ports[0]}"

        else:  # if more than 1 port in ports_to_scan
            expanded_ports = []
            for port in ports:
                if '*' in port:  # ignore it at this point
                    continue
                if '-' in port:  # if the ports contain a range
                    start_port, end_port = map(int, port.split('-'))
                    expanded_ports.extend(range(start_port, end_port + 1))
                else:  # if the port is a single port just add it to the list as normal
                    expanded_ports.append(port)
            ports_to_scan = ','.join(map(str, expanded_ports))
            command += f" -p {ports_to_scan}"

    elif ports_to_scan == '':  # if the user has not specified any ports to scan use top 1k as default
        command += f" --top-ports 1000"

    # scan type parsing logic
    if scan_type == 'SYN':
        command += f" -sS"
    elif scan_type == 'UDP':
        command += f" -sU"
    elif scan_type == 'TCP':
        command += f" -sT"

    # aggressive scan parsing logic
    if aggressive_scan == 'True':
        command += f" -A"

    # scan speed parsing logic
    if scan_speed:
        command += f" -T{scan_speed}"

    # os detection parsing logic
    if os_detection == 'True':
        command += f" -O"

    # todo logic here for the output file, eg if the user wants to save the output to a file, then change it from this:
    #   because the file in the form `-oX flaskr/static/temp/nmap-{target}.xml` is used in the is_target_webpage function, so if the user wants to save the output
    #       to a file, then we should copy that custom file to that one^

    command += f" -oX flaskr/static/temp/nmap-{target}.xml"

    command += f" {target}"
    return command


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


def run_ffuf_subdomain(target: str, wordlist_filepath: str, delay=0) -> str:
    """
    Runs ffuf to find subdomains. WARNING: remember to remove 'www.' from the target before running this function.
    :param wordlist_filepath: The path to the wordlist file.
    :param delay: An optional delay to add between requests.
    :param target: The target to run ffuf on.
    :return: The output of the ffuf tool as a string or a CalledProcessError.
    """
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
    print(f'{COLOURS["warn"]} End of ffuf webpage enumeration! {COLOURS["end"]}')
    return f"Using wordlist: {wordlist_filepath}:\n\n{result}"

def run_ffuf_webpage(target: str, wordlist_filepath: str, delay = 0) -> str:
    """
    Runs ffuf to find webpages.
    :param wordlist_filepath: The path to the wordlist file.
    :param delay: An optional delay to add between requests.
    :param target: The target to run ffuf on.
    :return: The output of the ffuf tool as a string or a CalledProcessError.
    """
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

def get_ipv4_addresses(domain: str) -> List[str]:
    """
    Get the IPv4 addresses for a domain using the dig command.
    :param domain: The domain to get the IPv4 addresses for.
    :return: A list of IPv4 addresses.
    """
    result = subprocess.run(['dig', domain, 'A', '+short'], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    ipv4_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    ipv4_addresses = [line for line in output.split('\n') if ipv4_pattern.match(line)]
    return ipv4_addresses


def run_smbclient(target: str) -> IO[str | bytes] | None | str:
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
        result = run_command_live_output_with_input(command, '\n')
        if result is not None:
            if result.returncode == 1:
                return result.stderr
            else:
                return result.stdout
        else:
            return f'{COLOURS["warn"]} smbclient failed to list shares. {COLOURS["end"]}'
    except subprocess.CalledProcessError as e:
        error_message = f"An error occurred while executing '{command}': {e}\nError output: {e.stderr}"
        return error_message


def run_http_get(target: str) -> subprocess.Popen[str | bytes] | str:
    """
    Runs the http-get tool on the target.
    :param target: The target to run http-get on.
    :return: The output of the http-get tool as a string or a CalledProcessError.
    """
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
    if result.returncode != 0:
        return result
    else:
        return f'{COLOURS["cross"]} http-get encountered an error. Are you sure the target is correct and is hosting a valid webservice?\n'


def run_nikto(target: str) -> str:
    """
    Runs the nikto tool on the target.
    :param target: The target to run nikto on.
    :return: The output of the nikto tool as a string or a CalledProcessError.
    """
    command = f"nikto -host {target}"
    try:
        print(f'{COLOURS["warn"]} Nikto now running. {COLOURS["end"]}')
        result = run_command_live_output(command)
        # result = run_command_with_output_after(command)
        return result
    except subprocess.CalledProcessError as e:
        return f"An error occurred: {e}"


def run_showmount(target):
    try:
        command = f"showmount -e {target}"
        print(f"{COLOURS['warn']} showmount will now attempt to query the mount daemon on {target}{COLOURS['end']}")
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(e.stderr)


def get_robots_file(target: str) -> CompletedProcess[str] | CalledProcessError | Type[CompletedProcess]:
    """
    Gets the robots.txt file from the target website.
    :param target: The target server.
    :return: Returns the completed process.
    """
    print(f'{COLOURS["warn"]} Getting robots.txt file! {COLOURS["end"]}')
    attempts = [
        f'https://{target}/robots.txt',
        f'http://{target}/robots.txt',
    ]
    for url in attempts:
        try:
            r = run_command_with_output_after(f'curl {url}')
            if r.returncode == 0:
                return r
        except subprocess.TimeoutExpired:
            continue
    print(f'{COLOURS["warn"]} End of robots file! {COLOURS["end"]}')
    return CompletedProcess
    # return run_command_with_output_after(f'curl https://{target}/robots.txt')


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
