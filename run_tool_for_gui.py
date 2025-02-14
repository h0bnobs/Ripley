import json
import os
import tempfile
from typing import List, Dict
import concurrent.futures
from flask import current_app
from flaskr import get_db
from scripts.utils import COLOURS, remove_ansi_escape_codes, remove_leading_newline, is_wordpress_site
from scripts.chatgpt_call import make_chatgpt_api_call
from scripts.run_commands import run_command_no_output, run_command_with_output_after
from scanner_tools import (
    run_host, run_nmap, run_smbclient, run_ftp, get_screenshot,
    get_robots_file, run_dns_recon, run_ffuf_subdomain, is_target_webpage,
    run_ffuf_webpage, get_metasploit_modules, run_wpscan
)


def save_scan_results_to_tempfile(results: Dict) -> str:
    os.makedirs('flaskr/static/temp', exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir="flaskr/static/temp")
    with open(temp_file.name, 'w') as f:
        json.dump(results, f)
    return temp_file.name


def process_extra_commands(target: str, commands_file: str) -> List[str]:
    if not commands_file:
        return []

    try:
        with open(commands_file, 'r') as f:
            commands = [cmd.strip().replace('{target}', target) for cmd in f.readlines()]

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


def run_scans(target: str, config: Dict) -> Dict:
    nmap_settings = {k: config[k] for k in
                     ["ports_to_scan", "scan_type", "aggressive_scan", "scan_speed", "os_detection", "ping_hosts", "ping_method", "host_timeout"]}

    results = {
        'target': target,
        'host_output': run_host(target),
        'nmap_output': run_nmap(target, nmap_settings),
        'smbclient_output': remove_ansi_escape_codes(run_smbclient(target)),
        'ftp_result': 'Anonymous FTP allowed!' if run_ftp(target) else 'Anonymous FTP login not allowed!',
        'dns_recon_output': run_dns_recon(target),
        'metasploit_output': '\n'.join(' '.join(module.values()) for module in
                                       get_metasploit_modules(target)) or "No relevant metasploit modules found"
    }
    is_webpage = is_target_webpage(target)
    if is_webpage:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            webpage_tasks = {
                'ffuf_webpage': executor.submit(run_ffuf_webpage, target, config["ffuf_webpage_wordlist"],
                                                config["ffuf_delay"]),
                'robots': executor.submit(get_robots_file, target),
                'ffuf_subdomain': executor.submit(run_ffuf_subdomain,
                                                  target[4:] if target.startswith('www.') else target,
                                                  config["ffuf_subdomain_wordlist"],
                                                  config["ffuf_delay"]
                                                  ),
                'screenshot': executor.submit(get_screenshot, target),
                'wpscan': executor.submit(run_wpscan, target) if is_wordpress_site(target) else None
            }

            results.update({
                'webpages_found': remove_ansi_escape_codes(webpage_tasks['ffuf_webpage'].result()),
                'robots_file': webpage_tasks['robots'].result().stdout,
                'subdomain_enumeration': remove_ansi_escape_codes(webpage_tasks['ffuf_subdomain'].result()),
                'wpscan_output': remove_ansi_escape_codes(webpage_tasks['wpscan'].result()) if webpage_tasks[
                    'wpscan'] else "Not a WordPress site"
            })

            screenshot = webpage_tasks['screenshot'].result()
            if screenshot:
                os.makedirs('flaskr/static/screenshots', exist_ok=True)
                run_command_no_output(f'cp {screenshot} flaskr/static/screenshots/{target}.png')
                results['screenshot'] = f'static/screenshots/{target}.png'
            else:
                results['screenshot'] = "[*] Couldn't get a screenshot of the target!"
    else:
        results.update({
            'webpages_found': 'Target is not a webpage!',
            'robots_file': 'Target is not a webpage!',
            'subdomain_enumeration': 'Target is not a webpage!',
            'screenshot': '[*] Target is not a webpage!',
            'wpscan_output': 'Target is not a webpage!'
        })

    # Process extra commands if configured
    if extra_outputs := process_extra_commands(target, config.get('extra_commands_file')):
        results['extra_commands_output'] = extra_outputs

    # Get AI advice if enabled
    if config.get('disable_chatgpt_api', '').lower() != 'true':
        results['ai_advice'] = make_chatgpt_api_call(results)
    else:
        results['ai_advice'] = "ChatGPT is disabled or there is an issue with the config!"

    return results


def save_to_db(db, results: Dict, extra_commands: List[str] = None) -> None:
    db.execute(
        """INSERT INTO scan_results 
           (target, host_output, subdomains_found, webpages_found, dns_recon_output,
            nmap_output, smbclient_output, ftp_result, screenshot, robots_output, 
            ai_advice, wpscan_output, metasploit_output)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (results['target'], results['host_output'],
         remove_leading_newline(remove_ansi_escape_codes(results['subdomain_enumeration'])),
         remove_leading_newline(remove_ansi_escape_codes(results['webpages_found'])),
         results['dns_recon_output'], results['nmap_output'],
         results['smbclient_output'], results['ftp_result'],
         results.get('screenshot'), results.get('robots_file'),
         results.get('ai_advice'), results.get('wpscan_output'),
         results.get('metasploit_output'))
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

    def process_target(target: str) -> str:
        with app.app_context():
            results = run_scans(target, config)
            save_to_db(get_db(), results)
            return save_scan_results_to_tempfile(results)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        return list(executor.map(process_target, target_list))


def run_on_single_target(target_list: List[str], config: Dict) -> str:
    target = target_list[0]
    results = run_scans(target, config)
    save_to_db(get_db(), results)
    run_command_no_output(f'rm flaskr/static/temp/nmap-{target}.xml')
    return save_scan_results_to_tempfile(results)
