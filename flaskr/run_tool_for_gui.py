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
    get_robots_file, run_dns_recon, run_ffuf_subdomain, is_target_webpage, run_ffuf_webpage
from scripts.chatgpt_call import make_chatgpt_api_call
from scripts.run_commands import run_command_no_output, run_command_with_output_after
from scripts.utils import remove_ansi_escape_codes, gui_banner, COLOURS, remove_leading_newline
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
            tasks = []
            nmap_output = run_nmap(target, nmap_flags)
            # Check if target is a webpage
            is_webpage = is_target_webpage(target)
            if is_webpage:
                print(f'{COLOURS["warn"]} Target is a webpage. Starting ffuf tasks concurrently. {COLOURS["end"]}')
                with concurrent.futures.ThreadPoolExecutor() as ffuf_executor:
                    tasks.append(ffuf_executor.submit(run_ffuf_webpage, target, delay=0.2))
                    tasks.append(ffuf_executor.submit(get_robots_file, target))
                    subdomain_target = target[4:] if target.startswith('www.') else target
                    tasks.append(ffuf_executor.submit(run_ffuf_subdomain, subdomain_target))

            # Start all other methods
            tasks.append(run_host(target))
            tasks.append(remove_ansi_escape_codes(run_smbclient(target)))
            tasks.append(run_ftp(target))
            tasks.append(run_dns_recon(target))

            # Wait for all tasks to complete and gather results
            results = [task.result() if isinstance(task, concurrent.futures.Future) else task for task in tasks]

            # Extract ffuf results if applicable
            ffuf_webpage_output = results.pop(0) if is_webpage else None
            robots_output = results.pop(0).stdout if is_webpage else None
            ffuf_subdomain_output = results.pop(0) if is_webpage else None

            # Collect other results
            host_output, smbclient_output, ftp_allowed, dns_recon_output = results

            ftp_string = ('Anonymous FTP allowed!', 'light_green') if ftp_allowed else colored(
                'Anonymous FTP login not allowed!', 'red')
            print(ftp_string)

            if is_webpage:
                print(f'{COLOURS["warn"]} Getting screenshot for {target}! {COLOURS["end"]}')
                screenshot_filepath = get_screenshot(target)
                if screenshot_filepath:
                    os.makedirs('flaskr/static/screenshots', exist_ok=True)
                    run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
                    print(
                        f"{colored('Screenshot acquired and is stored in:', 'green')} {colored(f'flaskr/static/screenshots/{target}.png\n', 'red')}")
            else:
                print(f'{COLOURS["warn"]} Target is not a webpage, skipping screenshot, subdomain/web page enumeration and the robots file! {COLOURS["end"]}')
                screenshot_filepath = None
                robots_output = None
                ffuf_webpage_output = None
                ffuf_subdomain_output = None
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
            result["ai_advice"] = ai_advice
            temp_file_path = save_scan_results_to_tempfile(result)
            print(ai_advice)
            db = get_db()
            db.execute(
                "INSERT INTO scan_results (target, host_output, subdomains_found, webpages_found, dns_recon_output, nmap_output, smbclient_output, ftp_result, screenshot, "
                "robots_output, ai_advice) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            return temp_file_path

    file_paths = []
    a = current_app._get_current_object()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_target, a, target): target for target in target_list}
        for future in concurrent.futures.as_completed(futures):
            file_paths.append(future.result())
    return file_paths


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

    # right here we do the extra command(s) execution, then add it to result.
    # get all the commands from flaskr/static/temp/extra_commands.txt, add the single target
    with open('flaskr/static/temp/extra_commands.txt', 'r') as f:
        extra_commands = [command.strip().replace('{target}', target) for command in f.readlines()]

    if extra_commands:
        command_output = []
        for command in extra_commands:
            command = f'{command.strip()}'
            print(f'{COLOURS["warn"]} Running extra command: {command}!{COLOURS["end"]}')
            command_output.append(remove_ansi_escape_codes(run_command_with_output_after(command).stdout))

        result["extra_commands_output"] = command_output
        ai_advice = make_chatgpt_api_call(result)
        result["ai_advice"] = ai_advice
        filepath = save_scan_results_to_tempfile(result)
        #print(ai_advice)
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

        scan_num = db.execute("SELECT MAX(scan_num) FROM scan_results").fetchone()[0]

        for command in extra_commands:
            db.execute(
                "INSERT INTO extra_commands (scan_num, command, command_output) VALUES (?, ?, ?)",
                (scan_num, command.strip(), command_output.pop(0))
            )
        db.commit()
    else:
        ai_advice = make_chatgpt_api_call(result)
        result["ai_advice"] = ai_advice
        filepath = save_scan_results_to_tempfile(result)
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