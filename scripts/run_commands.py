"""
Defines methods that take bash commands as inputs, and runs them as if they were given to the terminal.
"""
import subprocess
import time

def run_command_with_output_after(command):
    """
    Runs the given bash command and prints the output once the command has finished running.
    :param command: Bash command to run.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
        print(f'\n{result.stdout}')
    except subprocess.CalledProcessError as e:
        print(e)

def run_command_no_output(command):
    """
    Runs the given bash command with no terminal output.
    :param command: Bash command to run.
    """
    try:
        subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        print(e)

def run_command_live_output(command):
    """
    Runs the given bash command with a live output.
    :param command: Bash command to run.
    """
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')
        process.stdout.close()
        process.wait()
        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)
    except subprocess.CalledProcessError as e:
        print(f"Command {command} failed with error: {e.stderr}")


def run_command_live_output_with_input(command, input_data, delay=0.5):
    """
    Runs the given bash command with a live output, along with an input to that command after a 0.5s delay.
    :param delay: Optional delay in seconds for the input to be given.
    :param command: Bash command to run.
    :param input_data: The input that is to be given to the bash command.
    """
    try:
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        time.sleep(delay)
        stdout_data, stderr_data = process.communicate(input=input_data)
        print(stdout_data, end='')
        if process.returncode != 0:
            print(stderr_data, end='')
            raise subprocess.CalledProcessError(process.returncode, command, stderr_data)
    except subprocess.CalledProcessError as e:
        print(f"Command {command} failed with error: {e.stderr}")
