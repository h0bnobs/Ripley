import threading
import itertools
import sys
import time
import json
from termcolor import colored
import re
import os
import xml.etree.ElementTree as ET

from scripts.run_commands import run_command_with_output_after, run_command_no_output

COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m",
    "redStart": "\e[31m",
    "redEnd": "\e[0m",
    "greenStart": "\e[32m",
    "greenEnd": "\e[0m",
}

SPINNER_STATES = itertools.cycle(['-', '\\', '|', '/'])


class Spinner:
    """
    Class for the spinner, which runs when nmap is running.
    """
    def __init__(self):
        self.stop_event = threading.Event()
        self.spin_thread = threading.Thread(target=self.spin, daemon=True)

    def spin(self):
        sys.stdout.write(COLOURS["warn"] + " Nmap is now running and may take a while, be patient " + COLOURS["end"])
        while not self.stop_event.is_set():
            sys.stdout.write(next(SPINNER_STATES))
            sys.stdout.flush()
            sys.stdout.write('\b')
            time.sleep(0.1)

    def start(self):
        self.spin_thread.start()

    def stop(self):
        self.stop_event.set()
        self.spin_thread.join()
        sys.stdout.write('\b')


def cli_banner():
    """
    Banner for the cli tool.
    """
    banner_text = r"""
__________.__       .__                
\______   \__|_____ |  |   ____ ___.__.
 |       _/  \____ \|  | _/ __ <   |  |
 |    |   \  |  |_> >  |_\  ___/\___  |
 |____|_  /__|   __/|____/\___  > ____|
        \/   |__|             \/\/     

Usage: ripley_cli.py -c <config_file>
"""
    print(colored(f'{banner_text}', "light_blue"))


def gui_banner() -> str:
    """
    Banner for the gui.
    :return: The coloured banner text.
    """
    banner_text = r"""
__________.__       .__                
\______   \__|_____ |  |   ____ ___.__.
 |       _/  \____ \|  | _/ __ <   |  |
 |    |   \  |  |_> >  |_\  ___/\___  |
 |____|_  /__|   __/|____/\___  > ____|
        \/   |__|             \/\/     

"""
    return colored(f'{banner_text}', "light_blue")


def robots_string() -> str:
    """
    The robots.txt string.
    :return: The robots.txt string.
    """
    return f"""
{gui_banner()}
User-agent: *
Disallow: /

https://github.com/h0bnobs/Ripley
I love beesec
"""

def parse_config_file(filepath: str) -> dict:
    """
    Parses the JSON configuration file.
    :param filepath: The path to the configuration file.
    :return: The contents of the configuration file as a dictionary.
    """
    with open(filepath, "r") as f:
        config = json.load(f)
    return config


def remove_ansi_escape_codes(text) -> str:
    """
    Removes the ANSI escape codes from a string for nice outputs.
    :param text: The text to remove ANSI from.
    :return: The result string with no ANSI
    """
    #print(text)
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def find_full_filepath(directory: str, filename: str):
    """
    Finds the full filepath of a file in a given directory.
    :param directory: The directory to search.
    :param filename: The filename to search for.
    :return: The full filepath of the file or None if not found.
    """
    for root, dirs, files in os.walk(directory):
        if filename in files:
            return os.path.join(root, filename)
    return None

def parse_nmap_xml(xml_file: str, ports_to_check: list[int]) -> list[str]:
    """
    Parses the Nmap XML output file to check if certain ports are open on the target.
    :param xml_file: The path to the Nmap XML output file.
    :param ports_to_check: A list of ports to check.
    :return: A list of open ports.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    open_ports = []

    for host in root.findall('host'):
        addresses = host.findall('address')
        ip_address = None
        for address in addresses:
            if address.get('addrtype') == 'ipv4':
                ip_address = address.get('addr')
                break

        if ip_address is None:
            continue

        for port in host.findall('.//port'):
            port_id = port.get('portid')
            state = port.find('state').get('state')
            if state == 'open' and int(port_id) in ports_to_check:
                open_ports.append(port_id)

    return open_ports


def is_ip(target: str) -> bool:
    """
    Checks if the target is an IP address.
    :param target: The target to check.
    :return: True if the target is an IP address, False otherwise.
    """
    if not target or target == "":
        print("Target is empty or None")
        return False
    ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return ip_regex.match(target) is not None


def remove_leading_newline(text: str) -> str:
    """
    Removes a leading newline character from the start of the string if it exists.
    :param text: The input string.
    :return: The string without a leading newline character.
    """
    if text.startswith('\n'):
        return text[1:]
    return text

def get_extra_commands(filepath: str) -> list[str] | None:
    """
    Gets the extra commands from the file.
    :param filepath: The path to the file.
    :return: The list of extra commands, or None if the file is empty.
    """
    with open(filepath, "r") as f:
        lines = f.readlines()
    commands = [line.strip() for line in lines]
    return commands if commands else None

def is_wordpress_site(target: str) -> bool:
    """
    Checks if the URL is a Wordpress site and if that site has an open wp-admin page.
    :param target: The target to check.
    :return: True if the URL is a Wordpress site, False otherwise.
    """
    # cant use get_robots_file because of circular import.
    attempts = [
        f'https://{target}/robots.txt',
        f'http://{target}/robots.txt',
    ]
    for url in attempts:
        try:
            robots_file = run_command_no_output(f'curl {url}')
            if robots_file.returncode == 0:
                break
        except Exception as e:
            return False
    if robots_file:
        possible_strings = [
            "wp-admin",
            "wp-login",
            "wp-content",
            "wordpress"
        ]
        if any(s in robots_file.stdout.lower() for s in possible_strings):
            return True
    else:
        return False