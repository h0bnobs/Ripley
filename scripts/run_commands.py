"""
Defines methods that take bash commands as inputs, and runs them as if they were given to the terminal.
"""
import subprocess
import time


def run_command_with_input(command: str, input: str) -> str:
    """
    Runs the given bash command with the given input.
    :param command: Bash command to run.
    :param input: The input that is to be given to the bash command.
    :return: The stdout output if successful, otherwise raises an error with stderr.
    """
    try:
        process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        process.stdin.write(input)  # Send the input (e.g., pressing enter)
        process.stdin.flush()
        result = process.communicate()
        return result[0]
    except subprocess.CalledProcessError as e:
        return e

def run_command_with_output_after(command: str) ->  subprocess.CompletedProcess[str] | subprocess.CalledProcessError:
    """
    Runs the given bash command and prints the output once the command has finished running.
    :param command: Bash command to run.
    :return: The result object containing stdout and stderr.
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
        return result
    except subprocess.CalledProcessError as e:
        return e


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


def run_command_live_output(command: str) -> str:
    """
    Runs the given bash command with live output to the terminal.
    :param command: Bash command to run.
    :return: The stdout output if successful, otherwise raises an error with stderr.
    """
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout_output = []
        for stdout_line in iter(process.stdout.readline, ""):
            print(stdout_line, end='')  # Print live output
            stdout_output.append(stdout_line)  # Capture output

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()  # Capture stderr
            stdout_output.append(f"\nCommand {command} failed with error:\n{stderr_output}")
            return ''.join(stdout_output)

        # Join stdout and return as a string
        return ''.join(stdout_output)

    except subprocess.CalledProcessError as e:
        # Append the stderr output to the captured stdout
        stdout_output.append(f"\nCommand {command} failed with error:\n{e.stderr}")
        return ''.join(stdout_output)


def run_command_live_output_with_input(command, input_data, delay=0.5) -> subprocess.Popen[str | bytes]:
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

        # return both stdout and stderr as final result
        if process.returncode != 0:
            stderr_output = process.stderr.read()
            raise subprocess.CalledProcessError(process.returncode, command, stderr_output)
        else:
            return process
    except subprocess.CalledProcessError as e:
        # print error and return
        print(f"Command {command} failed with error: {e.stderr}")
        return e.stderr
