"""
Defines methods that take bash commands as inputs, and runs them as if they were given to the terminal.
"""
import subprocess


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
        process.stdin.write(input)  # send input
        process.stdin.flush()
        result = process.communicate()
        return result[0]
    except:
        return f"bash command failed {command}"


def run_command_with_output_after(command: str, verbose: str) -> subprocess.CompletedProcess[
                                                                     str] | subprocess.CalledProcessError:
    """
    Runs the given bash command and prints the output once the command has finished running.
    :param command: Bash command to run.
    :param verbose: Whether to print the output to the terminal.
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
        if verbose == "True":
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
    except:
        print(f"bash command failed {command}")


def run_command_live_output(command: str, verbose: str) -> str:
    """
    Runs the given bash command with live output to the terminal.
    :param command: Bash command to run.
    :param verbose: Whether to print the output to the terminal.
    :return: The stdout output if successful, otherwise raises an error with stderr.
    """
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout_output = []
        for stdout_line in iter(process.stdout.readline, ""):
            if verbose == "True":
                print(stdout_line, end='')
            stdout_output.append(stdout_line)

        process.stdout.close()
        process.wait()

        if process.returncode != 0:
            stderr_output = process.stderr.read()
            stdout_output.append(f"\nCommand {command} failed with error:\n{stderr_output}")
            return ''.join(stdout_output)

        return ''.join(stdout_output)
    except:
        return f"bash command failed {command}"
