"""
This script contains methods to run the tool for the gui. They are modified methods from the cli version so that they work in the gui version.
"""
from typing import List, Dict

from ripley_cli import run_host, run_nmap, run_http_get, run_smbclient, run_nikto
from scripts.utils import remove_ansi_escape_codes, gui_banner


def run_on_multiple_targets(target_list: List[str], config: Dict[str, str]) -> str:
    """
    Runs the tool for multiple targets given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    results = []
    for target in target_list:
        host_output = run_host(f"host {target}")
        nmap_flags = config['nmap_parameters']
        nmap_output = run_nmap(target, nmap_flags)
        httpget_output = remove_ansi_escape_codes(run_http_get(target))
        smbclient_output = run_smbclient(target)
        nikto_output = run_nikto(target)
        # run_showmount(target)

        results.append(f"{host_output} {nmap_output} {httpget_output} {smbclient_output} {nikto_output}")

    return "\n".join(results)


def run_on_single_target(target_list: List[str], config: Dict[str, str]) -> str:
    """
    Runs the tool on one target given as a list.
    :param target_list: The list of targets to run.
    :param config: The configuration file as a dictionary.
    :return: The concatenated string outputs of the tools.
    """
    target = target_list[0]  # assuming there is only one target in the list!
    nmap_flags = config['nmap_parameters']
    # todo do something with this:!!
    output_filename = f"{target}.xml"
    host_output = run_host(f"host {target}")
    nmap_output = run_nmap(target, nmap_flags)
    httpget_output = remove_ansi_escape_codes(run_http_get(target))
    smbclient_output = run_smbclient(target)
    nikto_output = run_nikto(target)

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
    # run_ftp(ftp_command, target)
    #

    return f'{gui_banner()} {nmap_output} {httpget_output} {smbclient_output} {nikto_output}'
