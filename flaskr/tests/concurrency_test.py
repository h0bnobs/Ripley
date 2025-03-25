import concurrent.futures
from subprocess import CompletedProcess
from typing import List, Dict

from scanner_tools import (
    run_host, run_nmap, run_smbclient, run_ftp, get_screenshot,
    get_robots_file, run_dns_recon, run_ffuf_subdomain, run_ffuf_webpage, check_security_headers, is_target_webpage,
    run_wpscan
)
from scripts.utils import *

scan_counter = 0
counter_lock = threading.Lock()


def run_on_multiple_targets_test(target_list: List[str], verbose: str) -> List[str]:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :param verbose: The verbose flag to run the tools in verbose mode.
    :return: The concatenated string outputs of the tools.
    """
    results: list[dict[str: str]] = []
    for target in target_list:
        host_output = run_host(target, verbose)
        nmap_output = run_nmap(target, {
            "ports_to_scan": "",
            "scan_type": "SYN",
            "aggressive_scan": "",
            "scan_speed": "5",
            "os_detection": "false",
            "ping_hosts": "false",
            "ping_method": "",
            "host_timeout": ""
        }, verbose)
        # webpage = is_target_webpage(target)
        # wpscan = run_wpscan(target)
        smbclient_output = remove_ansi_escape_codes(run_smbclient(target, verbose))
        ftp_allowed = run_ftp(target, verbose)
        ftp_string = f"Anonymous FTP login {'allowed' if ftp_allowed else 'not allowed'}"
        screenshot_filepath = get_screenshot(target, verbose)
        if screenshot_filepath:
            os.makedirs('flaskr/static/screenshots', exist_ok=True)
            run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
        robots_output = get_robots_file(target, verbose)
        dns_recon_output = run_dns_recon(target, verbose)
        ffuf_subdomain = run_ffuf_subdomain(target, "dnspod-top2000-sub-domains.txt", "true", verbose, 'False', delay=0)
        ffuf_webpage = run_ffuf_webpage(target, "Directories_Common.wordlist", "true", verbose, 'False', delay=0)
        headers = check_security_headers(target)
        result = {
            'target': target,
            'host_output': host_output,
            'dns_recon_output': dns_recon_output,
            'nmap_output': nmap_output,
            'smbclient_output': smbclient_output,
            'ftp_result': ftp_string,
            'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
            'robots_file': robots_output,
            'ffuf_subdomain': ffuf_subdomain,
            'ffuf_webpage': ffuf_webpage,
            # 'is_webpage': webpage,
            # 'wpscan': wpscan,
            'headers': headers
        }
        results.append(result)
        # result["ai_advice"] = make_chatgpt_api_call(result)
        # temp_file_path = tempfile(result)
        # file_paths.append(temp_file_path)

    return results


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

    results = {
        'target': target,
        'nmap_output': run_nmap(target, {
            "ports_to_scan": "",
            "scan_type": "SYN",
            "aggressive_scan": "",
            "scan_speed": "5",
            "os_detection": "false",
            "ping_hosts": "false",
            "ping_method": "",
            "host_timeout": ""
        }, verbose),
    }

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_key = {
            executor.submit(run_host, target, verbose): 'host_output',
            executor.submit(run_smbclient, target, verbose): 'smbclient_output',
            executor.submit(run_ftp, target, verbose): 'ftp_result',
            executor.submit(run_dns_recon, target, verbose): 'dns_recon_output',
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

    # Increment the counter and print the current count
    with counter_lock:
        scan_counter += 1
        print(f"Completed {target}: {scan_counter}/{total_scans}")
        if scan_counter == total_scans:
            scan_counter = 0
            total_scans = 0
    return results


def run_on_multiple_targets(target_list: List[str], config: Dict):
    """
    Run the tool on multiple targets.
    :param target_list: List of targets
    :param config: The configuration file as a dictionary.
    :return: The file path to the .txt file containing paths to the results.
    """

    total_scans = len(target_list)

    # clear temp dir
    for filename in os.listdir('flaskr/static/temp'):
        file_path = os.path.join('flaskr/static/temp', filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)

    def process_target(target: str):
        """
        Process a single target.
        :param target: The target to process.
        :returns The file path to the results.
        """
        results = run_scans(target, config, 0, config['verbose'], total_scans)
        results = {k: (v.stdout if isinstance(v, CompletedProcess) else v) for k, v in results.items()}
        return target

    # scan multiple targets concurrently
    with concurrent.futures.ThreadPoolExecutor() as executor:
        temp_file_paths = list(executor.map(process_target, target_list))


if __name__ == '__main__':
    config = {
        "targets": "bbc.co.uk, www.gov.uk, dailymail.co.uk, telegraph.co.uk, amazon.co.uk, google.co.uk, ox.ac.uk, news.bbc.co.uk, cam.ac.uk, guardian.co.uk, ico.org.uk, mirror.co.uk, service.gov.uk, www.nhs.uk, thesun.co.uk, thetimes.co.uk, express.co.uk, ucl.ac.uk",
        "config_filepath": "/home/max/PycharmProjects/Ripley/config.json",
        "ffuf_delay": "0.1",
        "ffuf_subdomain_wordlist": "dnspod-top2000-sub-domains.txt",
        "ffuf_webpage_wordlist": "Directories_Common.wordlist",
        "disable_chatgpt_api": "true",
        "ports_to_scan": "",
        "scan_type": "SYN",
        "aggressive_scan": "False",
        "scan_speed": "5",
        "os_detection": "False",
        "ping_hosts": "False",
        "ping_method": "",
        "host_timeout": "",
        "enable_ffuf": "True",
        "verbose": "True",
        "openai_api_key": "",
        "extra_commands": "",
        "chatgpt_model": "gpt-3.5-turbo",
        "ffuf_redirect": "False",
        "speed": "normal"
    }
    targets = ["bbc.co.uk", "www.gov.uk", "dailymail.co.uk", "telegraph.co.uk", "amazon.co.uk", "google.co.uk",
               "ox.ac.uk", "news.bbc.co.uk", "cam.ac.uk", "guardian.co.uk", "ico.org.uk", "mirror.co.uk",
               "service.gov.uk", "www.nhs.uk", "thesun.co.uk", "thetimes.co.uk", "express.co.uk", "ucl.ac.uk"]
    verbose = 'True'  # CHANGE THIS IF REQUIRED
    start = time.time()
    run_on_multiple_targets(targets, config)
    print(f"\nConcurrent scan took: {round(time.time() - start, 1)}s")

    start = time.time()
    non_concurrent = run_on_multiple_targets_test(targets, verbose)
    print(f"\n\nNon concurrent scan took: {round(time.time() - start, 1)}s")
