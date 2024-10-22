import threading
import itertools
import sys
import time
import json
from termcolor import colored
import re
import os

COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m",
    "redStart": "\e[31m",
    "redEnd": "\e[0m",
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


def parse_config_file(filepath: str) -> dict:
    """
    Parses the JSON configuration file.
    :param filepath: The path to the configuration file.
    :return: The contents of the configuration file as a dictionary.
    """
    with open(filepath, "r") as f:
        config = json.load(f)
    return config


def remove_ansi_escape_codes(text: str) -> str:
    """
    Removes the ANSI escape codes from a string for nice outputs.
    :param text: The text to remove ANSI from.
    :return: The result string with no ANSI
    """
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


def find_full_filepath(directory: str, filename: str):
    """

    :param directory:
    :param filename:
    :return:
    """
    for root, dirs, files in os.walk(directory):
        if filename in files:
            return os.path.join(root, filename)
    return None