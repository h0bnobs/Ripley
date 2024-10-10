import threading
import itertools
import sys
import time
import json

from termcolor import colored

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


def banner():
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

usage: ripley_cli.py -u <url>
"""
    print(colored(f'{banner_text}', "light_blue"))


def read_config_file(filepath):
    """
    Reads the JSON configuration file.
    :param filepath: The path to the configuration file.
    :return: The JSON of the configuration file.
    """
    with open(filepath, "r") as f:
        config = json.load(f)
    return config
