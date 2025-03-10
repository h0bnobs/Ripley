import time
from typing import List, Dict
from scanner_tools import (
    run_host, run_nmap, run_smbclient, run_ftp, get_screenshot,
    get_robots_file, run_dns_recon, run_ffuf_subdomain, is_target_webpage,
    run_ffuf_webpage, get_metasploit_modules, run_wpscan, check_security_headers
)
from scripts.utils import *
from scripts.run_commands import *


def run_on_multiple_targets_test(target_list: List[str]) -> List[str]:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    results: list[dict[str: str]] = []
    for target in target_list:
        host_output = run_host(target)
        nmap_output = run_nmap(target, {
            "ports_to_scan": "",
            "scan_type": "SYN",
            "aggressive_scan": "",
            "scan_speed": "3",
            "os_detection": "false",
            "ping_hosts": "false",
            "ping_method": "",
            "host_timeout": ""
        })
        #webpage = is_target_webpage(target)
        #wpscan = run_wpscan(target)
        smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
        ftp_allowed = run_ftp(target)
        ftp_string = f"Anonymous FTP login {'allowed' if ftp_allowed else 'not allowed'}"
        screenshot_filepath = get_screenshot(target)
        if screenshot_filepath:
            os.makedirs('flaskr/static/screenshots', exist_ok=True)
            run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
        robots_output = get_robots_file(target)
        dns_recon_output = run_dns_recon(target)
        ffuf_subdomain = run_ffuf_subdomain(target, "dnspod-top2000-sub-domains.txt", "true", delay=0)
        ffuf_webpage = run_ffuf_webpage(target, "Directories_Common.wordlist", "true", delay=0)
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
            #'is_webpage': webpage,
            #'wpscan': wpscan,
            'headers': headers
        }
        results.append(result)
        #result["ai_advice"] = make_chatgpt_api_call(result)
        #temp_file_path = tempfile(result)
        #file_paths.append(temp_file_path)

    return results

def tempfile(results: Dict) -> str:
    os.makedirs('flaskr/static/temp', exist_ok=True)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json", dir="flaskr/static/temp")
    with open(temp_file.name, 'w') as f:
        json.dump(results, f)
    return temp_file.name

if __name__ == '__main__':
    targets = ["google.com", "youtube.com", "facebook.com", "wikipedia.org", "instagram.com",
                                      "reddit.com", "bing.com", "x.com", "whatsapp.com", "taboola.com", "chatgpt.com",
                                      "yahoo.com", "amazon.com", "yandex.ru", "twitter.com", "duckduckgo.com", "yahoo.co.jp",
                                      "tiktok.com", "msn.com", "netflix.com", "weather.com", "live.com", "microsoftonline.com",
                                      "naver.com", "linkedin.com"]
    start = time.time()
    l = run_on_multiple_targets_test(targets)
    for target in targets:
        print(", ".join(targets))
    print(f"\n\nnon concurrent scan took: {round(time.time() - start, 1)}s")
