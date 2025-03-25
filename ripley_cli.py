"""
CLI version of the tool. Should be run after the gui has been run for the first time as that will set the db up.
If a scan is done from the CLI, the results will be saved to the db and can be viewed in the GUI.
It's recommended to set verbose to True in the config either directly in the JSON or just through the GUI.
"""
import argparse

from flaskr.flask_app import create_app, parse_targets
from run_tool_for_gui import run_on_multiple_targets, run_on_single_target
from scripts.utils import (
    parse_config_file, cli_banner
)


def parse_args() -> argparse.Namespace:
    """
    Get the CLI args.
    :return: The CLI args.
    """
    parser = argparse.ArgumentParser(description="ripley - One stop basic web app scanner.")
    parser.add_argument("-c", "--config", dest="config", required=False, help="Config text file")
    return parser.parse_args()


def main():
    """
    Run essentially the same way as the gui, just without the actual gui part.
    """
    app = create_app()
    with app.app_context():
        args = parse_args()
        if not args.config:
            raise Exception("You must use -c to specify a configuration file!")

        config = parse_config_file(args.config)
        if config is None:
            raise Exception("Config is null!")

        if config['verbose'] == 'False':
            print("Please note that you have verbose set to False. This means that you will not see any output from the tool. Please consider setting this value to true for better results.")
        unparsed_targets = config.get('targets', '').strip().split(', ')
        full_target_list = parse_targets(unparsed_targets)

        if not full_target_list:
            raise Exception("Target list empty!")

        if len(full_target_list) > 1:
            run_on_multiple_targets(full_target_list, config)
        else:
            run_on_single_target(full_target_list, config)


if __name__ == "__main__":
    cli_banner()
    main()
