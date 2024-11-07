"""
This script contains methods to run the tool for the gui. They are modified methods from the cli version so that they work in the gui version.
"""
import json
import os
import tempfile
from typing import List, Dict

from ripley_cli import run_host, run_nmap, run_http_get, run_smbclient, run_nikto, run_ftp, get_screenshot, \
    get_robots_file, run_dns_recon
from scripts.chatgpt_call import make_api_call
from scripts.run_commands import run_command_no_output
from scripts.utils import remove_ansi_escape_codes, gui_banner, COLOURS


def run_on_multiple_targets(target_list: List[str], config: Dict[str, str]) -> List[str]:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    file_paths = []
    for target in target_list:
        nmap_flags = config['nmap_parameters']
        host_output = run_host(target)
        nmap_output = run_nmap(target, nmap_flags)
        smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
        ftp_allowed = run_ftp(target)
        ftp_string = f"Anonymous FTP login {'allowed' if ftp_allowed else 'not allowed'}"
        screenshot_filepath = get_screenshot(target)
        if screenshot_filepath:
            os.makedirs('flaskr/static/screenshots', exist_ok=True)
            run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
        robots_output = get_robots_file(target).stdout
        dns_recon_output = run_dns_recon(target)
        result = {
            'target': target,
            'host_output': host_output,
            'dns_recon_output': dns_recon_output,
            'nmap_output': nmap_output,
            'smbclient_output': smbclient_output,
            'ftp_result': ftp_string,
            'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
            'robots_file': robots_output
        }
        result["ai_advice"] = make_api_call(result)
        temp_file_path = save_scan_results_to_tempfile(result)
        file_paths.append(temp_file_path)

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
    # todo check if the target includes a webpage or not. If it isn't then exclude some tasks like getting the screenshot.
    target = target_list[0]  # assuming there is only one target in the list!
    nmap_flags = config['nmap_parameters']
    host_output = run_host(target)
    nmap_output = run_nmap(target, nmap_flags)
    smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
    ftp_allowed = run_ftp(target)
    ftp_string = f"Anonymous FTP login {'allowed' if ftp_allowed else 'not allowed'}"
    screenshot_filepath = get_screenshot(target)
    if screenshot_filepath:
        os.makedirs('flaskr/static/screenshots', exist_ok=True)
        run_command_no_output(f'cp {screenshot_filepath} flaskr/static/screenshots/{target}.png')
    robots_output = get_robots_file(target).stdout
    dns_recon_output = run_dns_recon(target)
    result = {
        'target': target,
        'host_output': host_output,
        'dns_recon_output': dns_recon_output,
        'nmap_output': nmap_output,
        'smbclient_output': smbclient_output,
        'ftp_result': ftp_string,
        'screenshot': f'static/screenshots/{target}.png' if screenshot_filepath else "[*] Couldn't get a screenshot of the target!",
        'robots_file': robots_output
    }
    result["ai_advice"] = make_api_call(result)
    temp_file_path = save_scan_results_to_tempfile(result)
    return temp_file_path
    # return {"target": target, "result": result}

    # nikto_output = run_nikto(target)

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
    #

    # results.append(f"{host_string}\n{host_output}\n{nmap_string}\n{nmap_output}\n{httpget_string}\n{smbclient_string}\n{smbclient_output}\n\n{ftp_string}\n\n{screenshot_string}\n")
    # return "\n".join(results)


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