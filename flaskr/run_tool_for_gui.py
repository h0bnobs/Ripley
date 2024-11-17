"""
This script contains methods to run the tool for the gui. They are modified methods from the cli version so that they work in the gui version.
"""
import json
import os
import tempfile
import time
from typing import List, Dict
from termcolor import colored
from flaskr import get_db
from ripley_cli import run_host, run_nmap, run_http_get, run_smbclient, run_nikto, run_ftp, get_screenshot, \
    get_robots_file, run_dns_recon, run_ffuf_subdomain, target_is_webpage
from scripts.chatgpt_call import make_chatgpt_api_call
from scripts.run_commands import run_command_no_output
from scripts.utils import remove_ansi_escape_codes, gui_banner, COLOURS
import concurrent.futures
from flask import current_app


def run_on_multiple_targets(target_list: List[str], config: Dict[str, str]) -> List[str]:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: A list of paths to the temp files generated.
    """
    def process_target(app, target: str) -> str:
        """
        Processes a single target.
        :param app: The flask app.
        :param target: The target to process.
        :return: The path to the temp file as a string.
        """
        with app.app_context():
            nmap_flags = config['nmap_parameters']
            host_output = run_host(target)
            nmap_output = run_nmap(target, nmap_flags)
            smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
            print("")
            print(f'{COLOURS["warn"]} Attempting to connect to ftp anonymously! {COLOURS["end"]}')
            ftp_allowed = run_ftp(target)
            ftp_string = ('Anonymous FTP allowed!', 'light_green') if ftp_allowed else colored(
                'Anonymous FTP login not allowed!', 'red')
            print(ftp_string)
            if target_is_webpage(target):
                print(f'{COLOURS["warn"]} Getting robots.txt file! {COLOURS["end"]}')
                robots_output = get_robots_file(target).stdout
                print(f'{COLOURS["warn"]} End of robots file. {COLOURS["end"]}\n')
                if target.startswith('www.'):
                    ffuf_temp_target = target[4:]
                else:
                    ffuf_temp_target = target
                print(f'{COLOURS["warn"]} Attempting to find subdomains for {ffuf_temp_target}! {COLOURS["end"]}')
                ffuf_subdomain_output = run_ffuf_subdomain(ffuf_temp_target)
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
                'dns_recon_output': dns_recon_output,
                'nmap_output': nmap_output,
                'smbclient_output': smbclient_output,
                'ftp_result': ftp_string,
                'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
                'robots_file': robots_output
            }
            ai_advice = make_chatgpt_api_call(result)
            result["ai_advice"] = ai_advice
            temp_file_path = save_scan_results_to_tempfile(result)
            print(ai_advice)
            db = get_db()
            db.execute(
                "INSERT INTO scan_results (target, host_output, subdomains_found, nmap_output, smbclient_output, ftp_result, screenshot, "
                "robots_output, ai_advice) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (target,
                 host_output,
                 ffuf_subdomain_output,
                 nmap_output,
                 smbclient_output,
                 ftp_string,
                 screenshot_filepath,
                 robots_output,
                 ai_advice))
            db.commit()
            return temp_file_path

    file_paths = []
    a = current_app._get_current_object()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_target, a, target): target for target in target_list}
        for future in concurrent.futures.as_completed(futures):
            file_paths.append(future.result())
    return file_paths
    # dns_recon_output = run_dns_recon(target)
        # dns_recon_string = f'[*] dnsrecon output:'


        # nikto comes back with errors most of the time. mainly these:
        # + ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
        # + Scan terminated: 19 error(s) and 2 item(s) reported on remote host
        # nikto_output = run_nikto(target)

    #     results.append(f"{host_string}\n{host_output}\n{nmap_string}\n{nmap_output}\n{httpget_string}\n{httpget_output}\n{smbclient_string}"
    #                    f"\n{smbclient_output}\n{ftp_string}\n{screenshot_string}\n{robots_string}\n")
    # return "\n".join(results)


def run_on_single_target(target_list: List[str], config: Dict[str, str]) -> str:
    """
    Runs the tool on one target given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    target = target_list[0]  # assuming there is only one target in the list!
    nmap_flags = config['nmap_parameters']
    host_output = run_host(target)
    nmap_output = run_nmap(target, nmap_flags)
    smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
    print("")
    print(f'{COLOURS["warn"]} Attempting to connect to ftp anonymously! {COLOURS["end"]}')
    ftp_allowed = run_ftp(target)
    ftp_string = ('Anonymous FTP allowed!', 'light_green') if ftp_allowed else colored(
        'Anonymous FTP login not allowed!', 'red')
    print(ftp_string)
    if target_is_webpage(target):
        print(f'{COLOURS["warn"]} Getting robots.txt file! {COLOURS["end"]}')
        robots_output = get_robots_file(target).stdout
        print(f'{COLOURS["warn"]} End of robots file. {COLOURS["end"]}\n')
        if target.startswith('www.'):
            ffuf_temp_target = target[4:]
        else:
            ffuf_temp_target = target
        print(f'{COLOURS["warn"]} Attempting to find subdomains for {ffuf_temp_target}! {COLOURS["end"]}')
        ffuf_subdomain_output = run_ffuf_subdomain(ffuf_temp_target)
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
        'dns_recon_output': dns_recon_output,
        'nmap_output': nmap_output,
        'smbclient_output': smbclient_output,
        'ftp_result': ftp_string,
        'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
        'robots_file': robots_output
    }
    ai_advice = make_chatgpt_api_call(result)
    result["ai_advice"] = ai_advice
    filepath = save_scan_results_to_tempfile(result)
    print(ai_advice)
    db = get_db()
    db.execute(
        "INSERT INTO scan_results (target, host_output, subdomains_found, nmap_output, smbclient_output, ftp_result, screenshot, "
        "robots_output, ai_advice) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target,
         host_output,
         ffuf_subdomain_output,
         nmap_output,
         smbclient_output,
         ftp_string,
         screenshot_filepath,
         robots_output,
         ai_advice))
    db.commit()
    return filepath


def save_scan_results_to_tempfile(results: dict[str: str]) -> str:
    """
    Creates a temp json file with the contents of the output for that target. It takes the results and puts it into a json file.
    :param results: The results from the
    :return:
    """
    # create temp file and write the results
    os.makedirs('flaskr/static/temp', exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir="flaskr/static/temp")
    with open(temp_file.name, 'w') as f:
        json.dump(results, f)
    return temp_file.name