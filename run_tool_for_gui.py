import concurrent.futures
import json
import os
import subprocess
import tempfile
import threading
import time
from subprocess import CompletedProcess, SubprocessError
from typing import List, Dict

from flask import current_app

from flaskr.flask_app import get_db
from scanner_tools import (
    run_host, run_nmap, run_smbclient, run_ftp, get_screenshot,
    get_robots_file, run_dns_recon, run_ffuf_subdomain, is_target_webpage,
    run_ffuf_webpage, get_metasploit_modules, run_wpscan, check_security_headers
)
from scripts.chatgpt_call import make_chatgpt_api_call
from scripts.run_commands import run_command_with_output_after
from scripts.utils import COLOURS, remove_ansi_escape_codes, remove_leading_newline

scan_counter = 0
counter_lock = threading.Lock()


def save_scan_results_to_tempfile(results: Dict) -> str:
    """
    Save the results to a temporary file.
    :param results: The results to save.
    :return: The file path to the saved results.
    """
    os.makedirs('flaskr/static/temp', exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir="flaskr/static/temp")
    with open(temp_file.name, 'w') as f:
        json.dump(results, f)
    return temp_file.name


def start_msf_rpc(msf_password: str, verbose: str):
    """
    Start the Metasploit RPC server.
    :param msf_password: The default msfrpcd password.
    :param verbose: Whether to print the output to the terminal.
    :return: The process object.
    """
    # msfrpcd -P yourpassword -p 55553 -S
    if verbose == 'True':
        process = subprocess.Popen(['msfrpcd', '-P', msf_password, '-p', '55553', '-S'])
    else:
        process = subprocess.Popen(['msfrpcd', '-P', msf_password, '-p', '55553', '-S'], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    return process


def check_and_kill_msf_rpc(verbose: str):
    """
    Check if msfrpcd is running and if it is, kills it.
    :param verbose: Whether to print the output to the terminal.
    :return: None
    """
    try:
        result = subprocess.run(
            "pidof msfrpcd",
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
    except SubprocessError:
        return
    t = result.stdout.strip()
    if verbose == 'True':
        subprocess.run('kill ' + t, shell=True)
    else:
        subprocess.run('kill ' + t, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def process_extra_commands(target: str, extra_commands: str, verbose: str) -> List[str]:
    """
    Process extra commands from a string, replacing '{target}' with the actual target.
    :param target: The target to replace in commands.
    :param extra_commands: The string containing extra commands separated by commas.
    :param verbose: Whether to print extra command outputs.
    :return: A list of command outputs.
    """
    if not extra_commands:
        return []

    try:
        commands = [cmd.strip().replace('{target}', target) for cmd in extra_commands.split(', ')]

        if not commands:
            return []

        outputs = []
        for command in commands:
            if verbose == 'True':
                print(f'{COLOURS["warn"]} Running extra command: {command}!{COLOURS["end"]}')
            result = run_command_with_output_after(command, verbose)
            outputs.append(
                remove_ansi_escape_codes(result.stdout) if isinstance(result, CompletedProcess)
                else f"Command {command} failed: {remove_ansi_escape_codes(result.stderr)}"
            )
        return outputs
    except Exception as e:
        print(f"Error processing extra commands: {e}")
        return []


def run_scans(target: str, config: Dict, pid: int, verbose: str, total_scans: int) -> Dict:
    """
    Run all the scans on a target.
    :param target: The target to perform the scan on
    :param config: The config
    :param pid: The process id of the metasploit server
    :param verbose: Whether to print the output to the terminal.
    :return: The results of the scans
    """
    global scan_counter

    nmap_settings = {k: config[k] for k in
                     ["ports_to_scan", "scan_type", "aggressive_scan", "scan_speed", "os_detection", "ping_hosts",
                      "ping_method", "host_timeout"]}

    results = {
        'target': target,
        'nmap_output': run_nmap(target, nmap_settings, verbose),
    }

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_key = {
            executor.submit(run_host, target, verbose): 'host_output',
            executor.submit(run_smbclient, target, verbose): 'smbclient_output',
            executor.submit(run_ftp, target, verbose): 'ftp_result',
            executor.submit(run_dns_recon, target, verbose): 'dns_recon_output',
            executor.submit(get_metasploit_modules, target, pid, verbose): 'metasploit_output'
        }

        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
                if key == 'ftp_result':
                    results[key] = 'Anonymous FTP allowed!' if results[key] else 'Anonymous FTP login not allowed!'
                elif key == 'metasploit_output':
                    results[key] = '\n'.join(
                        ' '.join(module.values()) for module in results[key]) or "No relevant metasploit modules found"
            except Exception as e:
                results[key] = f"Error: {e}"

    is_webpage = is_target_webpage(target)
    if is_webpage:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            webpage_tasks = {
                'ffuf_webpage': executor.submit(run_ffuf_webpage, target, config["ffuf_webpage_wordlist"],
                                                config["enable_ffuf"], verbose, config["ffuf_redirect"],
                                                config["ffuf_delay"]),
                'robots_output': executor.submit(get_robots_file, target, verbose),
                'ffuf_subdomain': executor.submit(run_ffuf_subdomain,
                                                  target[4:] if target.startswith('www.') else target,
                                                  config["ffuf_subdomain_wordlist"],
                                                  config["enable_ffuf"], verbose, config["ffuf_redirect"],
                                                  config["ffuf_delay"]),
                'screenshot': executor.submit(get_screenshot, target, verbose),
                'wpscan': executor.submit(run_wpscan, target, verbose),
                'security_headers': executor.submit(check_security_headers, target)
            }

            for key, future in webpage_tasks.items():
                if future:
                    try:
                        results[key] = future.result()
                        if key in ['ffuf_webpage', 'ffuf_subdomain', 'wpscan']:
                            results[key] = remove_ansi_escape_codes(results[key])
                        if key == 'screenshot':
                            if results[key]:
                                results[key] = f'static/screenshots/{target}.png'
                            else:
                                results[key] = "[*] Couldn't get a screenshot of the target!"
                    except Exception as e:
                        results[key] = f"Error: {e}"

            results.update({
                'webpages_found': results.get('ffuf_webpage', 'Target is not a webpage!'),
                'robots_output': results.get('robots_output', 'Target is not a webpage!'),
                'subdomain_enumeration': results.get('ffuf_subdomain', 'Target is not a webpage!'),
                'wpscan_output': results.get('wpscan', 'Not a WordPress site')
            })
    else:
        results.update({
            'webpages_found': 'Target is not a webpage!',
            'robots_output': 'Target is not a webpage!',
            'subdomain_enumeration': 'Target is not a webpage!',
            'screenshot': 'Target is not a webpage!',
            'wpscan_output': 'Target is not a webpage!',
            'security_headers': 'Target is not a webpage!'
        })

    # process extra commands if configured
    extra_outputs = process_extra_commands(target, config.get('extra_commands'), config.get('verbose'))
    if extra_outputs:
        results['extra_commands_output'] = extra_outputs

    # make chatgpt api call if enabled
    if config.get('disable_chatgpt_api', '').lower() != 'true':
        extra_commands_output = results.get('extra_commands_output')
        results['ai_advice'] = make_chatgpt_api_call(results, config.get('chatgpt_model'), config.get("openai_api_key"))
        if extra_commands_output is not None:
            results['extra_commands_output'] = extra_commands_output
    else:
        results['ai_advice'] = "ChatGPT is disabled or there is an issue with the config!"

    # parse security headers and cookies into one string for html display
    final_str = ""
    if 'security_headers' in results and isinstance(results['security_headers'], dict):
        for header, value in results['security_headers'].items():
            if value != "":  # if there was a match for the headers we were looking for and the headers we found
                final_str += f"{header}: {value}\n"
        final_str += "\n"
        for header, value in results['security_headers'].items():
            if value == "":  # if there wasnt a match
                final_str += f"{header}: \n"
        results['security_headers'] = final_str

    # Increment the counter and print the current count
    with counter_lock:
        scan_counter += 1
        print(f"Completed {target}: {scan_counter}/{total_scans}")
        if scan_counter == total_scans:
            scan_counter = 0
            total_scans = 0
    return results


def save_to_db(db, results: dict, extra_commands: list[str] = None) -> None:
    """
    Save the results to the database.
    :param db: The database connection.
    :param results: The results to save.
    :param extra_commands: Extra commands to save.
    :return: None
    """
    db.execute(
        """INSERT INTO scan_results 
           (target, host_output, subdomains_found, webpages_found, dns_recon_output,
            nmap_output, smbclient_output, ftp_result, screenshot, robots_output, 
            ai_advice, wpscan_output, metasploit_output, security_headers)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (results['target'], results['host_output'],
         remove_leading_newline(remove_ansi_escape_codes(results['subdomain_enumeration'])),
         remove_leading_newline(remove_ansi_escape_codes(results['webpages_found'])),
         results['dns_recon_output'], results['nmap_output'],
         results['smbclient_output'], results['ftp_result'],
         results.get('screenshot'), results.get('robots_output'),
         results.get('ai_advice'), results.get('wpscan_output'),
         results.get('metasploit_output'), results.get('security_headers'))
    )
    db.commit()

    if extra_commands and 'extra_commands_output' in results:
        scan_num = db.execute("SELECT MAX(scan_num) FROM scan_results").fetchone()[0]
        for cmd, output in zip(extra_commands, results['extra_commands_output']):
            db.execute(
                "INSERT INTO extra_commands (scan_num, command, command_output) VALUES (?, ?, ?)",
                (scan_num, cmd.strip(), output)
            )
        db.commit()


def run_on_multiple_targets(target_list: List[str], config: Dict) -> str:
    """
    Run the tool on multiple targets.
    :param target_list: List of targets
    :param config: The configuration file as a dictionary.
    :return: The file path to the .txt file containing paths to the results.
    """
    app = current_app._get_current_object()

    check_and_kill_msf_rpc(config['verbose'])
    msf_process = start_msf_rpc('msf', config['verbose'])
    pid = msf_process.pid
    total_scans = len(target_list)

    # clear temp dir
    for filename in os.listdir('flaskr/static/temp'):
        file_path = os.path.join('flaskr/static/temp', filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)

    def process_target(target: str) -> str:
        """
        Process a single target.
        :param target: The target to process.
        :returns The file path to the results.
        """
        with app.app_context():
            results = run_scans(target, config, pid, config['verbose'], total_scans)
            results = {k: (v.stdout if isinstance(v, CompletedProcess) else v) for k, v in results.items()}
            extra_commands: list = config['extra_commands'].split(', ')
            save_to_db(get_db(), results, extra_commands=extra_commands)
            return save_scan_results_to_tempfile(results)

    # scan multiple targets concurrently
    max_workers = None if config['speed'] == 'normal' else round(os.cpu_count() / 2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        temp_file_paths = list(executor.map(process_target, target_list))

    # a .txt file to store all temp file paths
    temp_file_list_path = 'flaskr/static/temp/temp_file_paths.txt'
    with open(temp_file_list_path, 'w') as f:
        for path in temp_file_paths:
            f.write(f"{path}\n")

    return temp_file_list_path


def run_on_single_target(target_list: List[str], config: Dict) -> str:
    """
    Run the tool on a single target.
    :param target_list: List of targets which in this case is a list of 1 element
    :param config: The configuration file as a dictionary.
    :return: The file path to the results.
    """
    target = target_list[0]

    check_and_kill_msf_rpc(config['verbose'])
    msf_process = start_msf_rpc('msf', config['verbose'])
    pid = msf_process.pid

    # clear temp dir
    for filename in os.listdir('flaskr/static/temp'):
        file_path = os.path.join('flaskr/static/temp', filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)

    results = run_scans(target, config, pid, config['verbose'], len(target_list))
    results['smbclient_output'] = remove_ansi_escape_codes(results['smbclient_output'])
    results = {k: (v.stdout if isinstance(v, CompletedProcess) else v) for k, v in results.items()}
    extra_commands: list = config['extra_commands'].split(', ')
    save_to_db(get_db(), results, extra_commands=extra_commands)
    # run_command_no_output(f'rm flaskr/static/temp/nmap-{target}.xml')
    temp_file_path = save_scan_results_to_tempfile(results)

    # a .txt file to store the temp file path
    temp_file_list_path = 'flaskr/static/temp/temp_file_path.txt'
    with open(temp_file_list_path, 'w') as f:
        f.write(f"{temp_file_path}\n")

    return temp_file_list_path
