import json
import os
import subprocess
import tempfile
import time
from subprocess import CompletedProcess
from typing import List, Dict
import concurrent.futures
from flask import current_app
from flaskr import get_db
from scripts.utils import COLOURS, remove_ansi_escape_codes, remove_leading_newline, is_wordpress_site
from scripts.chatgpt_call import make_chatgpt_api_call
from scripts.run_commands import run_command_no_output, run_command_with_output_after, run_command_with_input
from scanner_tools import (
    run_host, run_nmap, run_smbclient, run_ftp, get_screenshot,
    get_robots_file, run_dns_recon, run_ffuf_subdomain, is_target_webpage,
    run_ffuf_webpage, get_metasploit_modules, run_wpscan, check_security_headers
)


def save_scan_results_to_tempfile(results: Dict) -> str:
    os.makedirs('flaskr/static/temp', exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir="flaskr/static/temp")
    with open(temp_file.name, 'w') as f:
        json.dump(results, f)
    return temp_file.name

def start_msf_rpc(msf_password: str):
    print("[*] Starting Metasploit RPC Server...")
    # msfrpcd -P yourpassword -p 55553 -S
    process = subprocess.Popen(['msfrpcd', '-P', msf_password, '-p', '55553', '-S'])
    time.sleep(4)
    return process

def check_and_kill_msf_rpc():
    print("[*] Checking for existing Metasploit RPC Server...")
    result = subprocess.run(
        "ps aux | grep msfrpcd",
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    t = result.stdout.split('\n')
    subprocess.run('kill ' + t[0].split()[1], shell=True)

def process_extra_commands(target: str, commands_file: str) -> List[str]:
    """
    Process extra commands from a file, replacing '{target}' with the actual target.
    :param target: The target to replace in commands.
    :param commands_file: The file containing extra commands.
    :return: A list of command outputs.
    """
    if not commands_file:
        return []

    try:
        with open(commands_file, 'r') as f:
            commands = [cmd.strip().replace('{target}', target) for cmd in f.readlines()]

        if not commands:
            return []

        outputs = []
        for command in commands:
            print(f'{COLOURS["warn"]} Running extra command: {command}!{COLOURS["end"]}')
            result = run_command_with_output_after(command)
            outputs.append(
                remove_ansi_escape_codes(result.stdout) if result.returncode == 0
                else f"Command {command} failed: {remove_ansi_escape_codes(result.stderr)}"
            )
        return outputs
    except Exception as e:
        print(f"Error processing extra commands: {e}")
        return []


def run_scans(target: str, config: Dict, pid: int) -> Dict:
    nmap_settings = {k: config[k] for k in
                     ["ports_to_scan", "scan_type", "aggressive_scan", "scan_speed", "os_detection", "ping_hosts", "ping_method", "host_timeout"]}

    #run_command_with_input('smbclient -L 10.129.32.234', '\n')

    results = {
        'target': target,
        'nmap_output': run_nmap(target, nmap_settings),
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_key = {
            executor.submit(run_host, target): 'host_output',
            executor.submit(run_smbclient, target): 'smbclient_output',
            executor.submit(run_ftp, target):  'ftp_result',
            executor.submit(run_dns_recon, target): 'dns_recon_output',
            executor.submit(get_metasploit_modules, target, pid): 'metasploit_output'
        }

        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
                if key == 'ftp_result':
                    results[key] = 'Anonymous FTP allowed!' if results[key] else 'Anonymous FTP login not allowed!'
                elif key == 'metasploit_output':
                    results[key] = '\n'.join(' '.join(module.values()) for module in results[key]) or "No relevant metasploit modules found"
            except Exception as e:
                results[key] = f"Error: {e}"

    is_webpage = is_target_webpage(target)
    if is_webpage:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            webpage_tasks = {
                'ffuf_webpage': executor.submit(run_ffuf_webpage, target, config["ffuf_webpage_wordlist"],
                                                config["enable_ffuf"], config["ffuf_delay"]),
                'robots_output': executor.submit(get_robots_file, target),
                'ffuf_subdomain': executor.submit(run_ffuf_subdomain,
                                                  target[4:] if target.startswith('www.') else target,
                                                  config["ffuf_subdomain_wordlist"],
                                                  config["enable_ffuf"], config["ffuf_delay"]
                                                  ),
                'screenshot': executor.submit(get_screenshot, target),
                'wpscan': executor.submit(run_wpscan, target) if is_wordpress_site(target) else None,
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
                                os.makedirs('flaskr/static/screenshots', exist_ok=True)
                                run_command_no_output(f'cp {results[key]} flaskr/static/screenshots/{target}.png')
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

    # Process extra commands if configured
    if extra_outputs := process_extra_commands(target, config.get('extra_commands_file')):
        results['extra_commands_output'] = extra_outputs

    # Get AI advice if enabled
    if config.get('disable_chatgpt_api', '').lower() != 'true':
        results['ai_advice'] = make_chatgpt_api_call(results)
    else:
        results['ai_advice'] = "ChatGPT is disabled or there is an issue with the config!"

    # parse security headers and cookies into one string for html display
    final_str = ""
    if 'security_headers' in results:
        for header, value in results['security_headers'].items():
            if value != "":
                final_str += f"{header}: {value}\n"
        final_str += "\n"
        for header, value in results['security_headers'].items():
            if value == "":
                final_str += f"{header}: \n"
        results['security_headers'] = final_str

    return results


def save_to_db(db, results: Dict, extra_commands: List[str] = None) -> None:
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


def run_on_multiple_targets(target_list: List[str], config: Dict) -> List[str]:
    app = current_app._get_current_object()

    check_and_kill_msf_rpc()
    msf_process = start_msf_rpc('msf')
    pid = msf_process.pid

    def process_target(target: str) -> str:
        with app.app_context():
            results = run_scans(target, config, pid)
            results = {k: (v.stdout if isinstance(v, CompletedProcess) else v) for k, v in results.items()}
            save_to_db(get_db(), results)

            #from pprint import pprint
            #pprint({k: (v, type(v)) for k, v in results.items() if not isinstance(v, str)})
            return save_scan_results_to_tempfile(results)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        return list(executor.map(process_target, target_list))


def run_on_single_target(target_list: List[str], config: Dict) -> str:
    target = target_list[0]

    check_and_kill_msf_rpc()
    msf_process = start_msf_rpc('msf')
    pid = msf_process.pid

    results = run_scans(target, config, pid)
    results['smbclient_output'] = remove_ansi_escape_codes(results['smbclient_output'])
    results = {k: (v.stdout if isinstance(v, CompletedProcess) else v) for k, v in results.items()}
    save_to_db(get_db(), results)
    run_command_no_output(f'rm flaskr/static/temp/nmap-{target}.xml')
    return save_scan_results_to_tempfile(results)
