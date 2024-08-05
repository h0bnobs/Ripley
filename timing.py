import multiprocessing
import subprocess
import threading
import time
import os
import itertools
import sys

COLOURS = {
    "plus": "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]",
    "minus": "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]",
    "cross": "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]",
    "star": "\033[1;34m[*]\033[1;m",
    "warn": "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]",
    "end": "\033[1;m"
}

SPINNER_STATES = itertools.cycle(['-', '\\', '|', '/'])


class Spinner:
    def __init__(self):
        self.stop_event = threading.Event()
        self.spin_thread = threading.Thread(target=self.spin, daemon=True)

    def spin(self):
        sys.stdout.write(COLOURS["warn"] + " Running, be patient " + COLOURS["end"])
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


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error executing '{command}': {e}")
        print(e.stderr)


def prepare_commands_file():
    commands = [
        "rm index.html",
        "nmap www.beesec.co.uk",
        "python http-get-ripley.py -i targets_for_ripley.txt",
        "nmap www.google.co.uk",
        "nmap www.reddit.com",
        "nmap www.beesec.co.uk",
        "nmap www.google.co.uk",
        "nmap www.reddit.com",
        "python http-get-ripley.py -i targets_for_ripley.txt",
        "nmap x.com",
        "nmap www.youtube.com",
        "locate CVE-2023-27163.sh",
        "top -n 1",
        "wget -q github.com",
        "rm index.html"
    ]

    with open("commands.txt", "w") as f:
        for command in commands:
            f.write(command + "\n")


def time_threading():
    prepare_commands_file()
    start_time = time.time()

    threads = []
    with open("commands.txt") as f:
        commands = f.readlines()

    for command in commands:
        thread = threading.Thread(target=run_command, args=(command.strip(),))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    elapsed_time = time.time() - start_time
    print(f"Threading took {elapsed_time:.2f} seconds")
    return elapsed_time


def time_multiprocessing():
    prepare_commands_file()
    start_time = time.time()

    processes = []
    with open("commands.txt") as f:
        commands = f.readlines()

    for command in commands:
        process = multiprocessing.Process(target=run_command, args=(command.strip(),))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    elapsed_time = time.time() - start_time
    print(f"Multiprocessing took {elapsed_time:.2f} seconds")
    return elapsed_time


def time_xargs():
    prepare_commands_file()
    start_time = time.time()

    try:
        result = subprocess.run("cat commands.txt | xargs -I CMD -P 6 sh -c CMD", shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"xargs command failed with return code {e.returncode}")
        print(f"Error output: {e.stderr}")

    elapsed_time = time.time() - start_time
    print(f"xargs took {elapsed_time:.2f} seconds")
    return elapsed_time


if __name__ == "__main__":
    threading_all = []
    multiprocessing_all = []
    xargs_all = []
    num_runs = 30

    for _ in range(num_runs):
        print("############### Threading starting: ###############")
        threading_time = time_threading()
        print("############### Multiprocessing starting: ###############")
        multiprocessing_time = time_multiprocessing()
        print("############### xargs starting: ###############")
        xargs_time = time_xargs()

        threading_all.append(threading_time)
        multiprocessing_all.append(multiprocessing_time)
        xargs_all.append(xargs_time)

    print("Threading times: " + str(threading_all))
    print("Multiprocessing times: " + str(multiprocessing_all))
    print("Xargs times: " + str(xargs_all))


    # Calculate and print averages
    def calculate_average(times):
        return sum(times) / len(times) if times else 0


    avg_threading = calculate_average(threading_all)
    avg_multiprocessing = calculate_average(multiprocessing_all)
    avg_xargs = calculate_average(xargs_all)

    print(f"Average time for threading: {avg_threading:.2f} seconds")
    print(f"Average time for multiprocessing: {avg_multiprocessing:.2f} seconds")
    print(f"Average time for xargs: {avg_xargs:.2f} seconds")

    # Cleanup
    if os.path.exists("commands.txt"):
        os.remove("commands.txt")
