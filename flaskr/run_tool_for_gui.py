"""
This script contains methods to run the tool for the gui. They are modified methods from the cli version so that they work in the gui version.
"""
from typing import List, Dict

from pexpect.screen import screen

from ripley_cli import run_host, run_nmap, run_http_get, run_smbclient, run_nikto, run_ftp, get_screenshot, \
    get_robots_file, run_dns_recon
from scripts.run_commands import run_command_no_output
from scripts.utils import remove_ansi_escape_codes, gui_banner, COLOURS


def run_on_multiple_targets(target_list: List[str], config: Dict[str, str]) -> str:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    results = []
    for target in target_list:
        nmap_flags = config['nmap_parameters']
        host_string = f'[*] Output of the host command:'
        host_output = run_host(target)
        nmap_string = f'[*] Output of the nmap scan:'
        nmap_output = run_nmap(target, nmap_flags)
        httpget_string = f'[*] Output of http-get scan:'

        # doesnt work, may want a rewrite.
        httpget_output = remove_ansi_escape_codes(str(run_http_get(target)))
        smbclient_string = f'[*] Output of smbclient scan:'
        smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
        b = run_ftp(target)
        ftp_string = remove_ansi_escape_codes(
            f'{COLOURS["star"]} Anonymous FTP login allowed!' if b else f'{COLOURS["warn"]} Anonymous FTP login not allowed!')
        filepath = get_screenshot(target)
        if filepath:
            run_command_no_output(f'cp {filepath} flaskr/static/screenshots/{target}.png')
            screenshot_string = f"[*] Managed to get a screenshot of the target!\n</pre><img src='static/screenshots/{target}.png'><pre>"
        else:
            screenshot_string = f"[*] Couldn't get a screenshot of the target!"
        # run_showmount(target)
        robots_output = get_robots_file(target)
        if robots_output.stdout:
            robots_string = f'[*] Contents of the robots file was found:\n {robots_output.stdout}'
        else:
            robots_string = "[*] Couldn't find the robots file!"
        dns_recon_output = run_dns_recon(target)
        dns_recon_string = f'[*] dnsrecon output:'


        # nikto comes back with errors most of the time. mainly these:
        # + ERROR: Error limit (20) reached for host, giving up. Last error: error reading HTTP response
        # + Scan terminated: 19 error(s) and 2 item(s) reported on remote host
        # nikto_output = run_nikto(target)

        results.append(f"{host_string}\n{host_output}\n{nmap_string}\n{nmap_output}\n{httpget_string}\n{httpget_output}\n{smbclient_string}"
                       f"\n{smbclient_output}\n{ftp_string}\n{screenshot_string}\n{robots_string}\n{dns_recon_string}\n{dns_recon_output}")
    return "\n".join(results)


def run_on_single_target(target_list: List[str], config: Dict[str, str]) -> str:
    """
    Runs the tool on one target given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    # todo check if the target includes a webpage or not. If it isn't then exclude some tasks like getting the screenshot.
    target = target_list[0]  # assuming there is only one target in the list!
    results = []
    nmap_flags = config['nmap_parameters']
    host_string = f'[*] Output of the host command:'
    host_output = run_host(target)
    nmap_string = f'[*] Output of the nmap scan:'
    nmap_output = run_nmap(target, nmap_flags)
    httpget_string = f'[*] Output of http-get scan:'

    # doesnt work, may want a rewrite.
    # httpget_output = remove_ansi_escape_codes(str(run_http_get(target)))
    smbclient_string = f'[*] Output of smbclient scan:'
    smbclient_output = remove_ansi_escape_codes(run_smbclient(target))
    b = run_ftp(target)
    ftp_string = remove_ansi_escape_codes(f'{COLOURS["star"]} Anonymous FTP login allowed!' if b else f'{COLOURS["warn"]} Anonymous FTP login not allowed!')
    filepath = get_screenshot(target)
    if filepath:
        run_command_no_output(f'cp {filepath} flaskr/static/screenshots/{target}.png')
        screenshot_string = f"[*] Managed to get a screenshot of the target!\n</pre><img src='static/screenshots/{target}.png'><pre>"
    else:
        screenshot_string = f"[*] Couldn't get a screenshot of the target!"


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

    results.append(f"{host_string}\n{host_output}\n{nmap_string}\n{nmap_output}\n{httpget_string}\n{smbclient_string}\n{smbclient_output}\n\n{ftp_string}\n\n{screenshot_string}\n")
    return "\n".join(results)
