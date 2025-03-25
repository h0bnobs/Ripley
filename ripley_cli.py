import argparse
import concurrent.futures
import os
from typing import List, Dict

from termcolor import colored

from flaskr.flask_app import create_app, parse_targets
from run_tool_for_gui import run_on_multiple_targets, run_on_single_target
from scanner_tools import (
    run_host, run_nmap, run_smbclient, run_ftp, run_dns_recon, run_ffuf_webpage, run_ffuf_subdomain, get_robots_file,
    get_screenshot
)
from scripts.run_commands import (
    run_command_no_output
)
from scripts.utils import (
    parse_config_file, remove_ansi_escape_codes, parse_nmap_xml, remove_leading_newline
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ripley - One stop basic web app scanner.")
    parser.add_argument("-c", "--config", dest="config", required=False, help="Config text file")
    return parser.parse_args()


def get_target_list(single_target: str, multiple_targets: List[str], targets_file: str) -> List[str]:
    if single_target:
        return [single_target]
    elif multiple_targets:
        return multiple_targets
    elif targets_file:
        with open(targets_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    return []


def is_target_webpage(target: str) -> bool:
    open_ports = parse_nmap_xml(f'flaskr/static/temp/nmap-{target}.xml', [80, 443, 8080, 8443])
    return any(port in open_ports for port in ['80', '443', '8080', '8443'])


def run_scan_tools(target: str, config: Dict[str, str], is_webpage: bool) -> dict:
    results = {
        'target': target,
        'host_output': run_host(target),
        'nmap_output': run_nmap(target, config),
        'smbclient_output': remove_ansi_escape_codes(run_smbclient(target)),
        'ftp_result': ('Anonymous FTP allowed!', 'light_green') if run_ftp(target) else
        colored('Anonymous FTP login not allowed!', 'red'),
        'dns_recon_output': run_dns_recon(target)
    }

    if is_webpage:
        results.update(run_webpage_scans(target, config, max_workers=30))
    else:
        results.update({
            'subdomain_enumeration': 'Target is not a webpage!',
            'webpages_found': 'Target is not a webpage!',
            'screenshot': '[*] Target is not a webpage!',
            'robots_file': 'Target is not a webpage!',
            'wpscan_output': 'Target is not a webpage!'
        })

    return results


def run_webpage_scans(target: str, config: Dict[str, str], max_workers: int = 10) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            'ffuf_webpage': executor.submit(run_ffuf_webpage, target, config.get("ffuf_webpage_wordlist"),
                                            config.get("ffuf_delay")),
            'robots': executor.submit(get_robots_file, target),
            'ffuf_subdomain': executor.submit(run_ffuf_subdomain, target.replace('www.', '', 1),
                                              config.get("ffuf_subdomain_wordlist"), config.get("ffuf_delay")),
            'screenshot': executor.submit(get_screenshot, target)
        }

        results = {
            'webpages_found': futures['ffuf_webpage'].result(),
            'robots_file': futures['robots'].result().stdout if futures['robots'].result() else "No robots.txt found",
            'subdomain_enumeration': futures['ffuf_subdomain'].result(),
        }

        screenshot = futures['screenshot'].result()
        if screenshot:
            os.makedirs('flaskr/static/screenshots', exist_ok=True)
            run_command_no_output(f'cp {screenshot} flaskr/static/screenshots/{target}.png')
            results['screenshot'] = f'static/screenshots/{target}.png'
        else:
            results['screenshot'] = "[*] Couldn't get a screenshot of the target!"

        return results


def save_to_db(db, results: dict) -> None:
    db.execute(
        """INSERT INTO scan_results 
           (target, host_output, subdomains_found, webpages_found, dns_recon_output,
            nmap_output, smbclient_output, ftp_result, screenshot, robots_output, ai_advice)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (results['target'], results['host_output'],
         remove_leading_newline(remove_ansi_escape_codes(results['subdomain_enumeration'])),
         remove_leading_newline(remove_ansi_escape_codes(results['webpages_found'])),
         results['dns_recon_output'], results['nmap_output'],
         results['smbclient_output'], results['ftp_result'],
         results.get('screenshot'), results.get('robots_file'),
         results.get('ai_advice', 'AI advice not available'))
    )
    db.commit()


def main():
    app = create_app()
    with app.app_context():
        args = parse_args()
        if not args.config:
            raise Exception("You must use -c to specify a configuration file!")

        config = parse_config_file(args.config)
        if config is None:
            raise Exception("Config is null!")

        unparsed_targets = config.get('targets', '').strip().split(', ')
        full_target_list = parse_targets(unparsed_targets)

        if not full_target_list:
            raise Exception("Target list empty!")

        if len(full_target_list) > 1:
            run_on_multiple_targets(full_target_list, config)
        else:
            run_on_single_target(full_target_list, config)


if __name__ == "__main__":
    main()
