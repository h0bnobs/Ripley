"""
This script initialises and configures a Flask application for running various network scanning tools.

It sets up the Flask app, configures routes for updating and displaying configurations, running scans on targets,
and displaying scan results. It also ensures the database is initialised and provides utility functions for
handling scan results and configurations.

Modules:
    flaskr.db: Manages the SQLite database connection and initialisation.
    run_tool_for_gui: Contains functions to run network scanning tools on single or multiple targets.
    scripts.utils: Provides utility functions for parsing configuration files and displaying banners.
"""
import ipaddress
import json
import os
import re
import time
import psutil

from flask import Flask, render_template, request, redirect, url_for, session, Response
from libnmap.parser import NmapParser

from flaskr.db import get_db, init_db
from run_tool_for_gui import run_on_multiple_targets, run_on_single_target
from scripts.run_commands import run_command_with_output_after
from scripts.utils import parse_config_file, robots_string


# flask --app flaskr init-db
# flask --app flaskr run --debug

def create_app(test_config=None) -> Flask:
    """
    Create and configure the Flask application.

    This function initialises the Flask app with necessary configurations, routes, and database connections.
    It also sets up the instance folder, applies the configuration (from a provided test config or the instance config),
    and ensures the database is initialised. Routes for updating and displaying configurations, running scans on targets,
    and displaying scan results are defined within this function.

    :param test_config: Optional dictionary containing test configuration settings to override the default app config.
    :type test_config: dict, optional
    :return: A Flask application instance.
    :rtype: Flask
    """

    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # sets configuration values for the Flask application. In this case, it sets SECRET_KEY and DATABASE.
    # DATABASE is set to the path of the SQLite database file, which is located in the instance folder of the Flask application.
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    app.route('/')(lambda: redirect(url_for('general_settings')))

    @app.route('/user-manual', methods=['GET'])
    def user_manual():
        """
        The route for the user manual.
        :return: The render template of the user manual html file.
        """
        page = request.args.get('page', 'general')  # default to general
        return render_template('user_manual.html', page=page)


    @app.route('/general-settings', methods=['GET'])
    def general_settings() -> str:
        """
        The route for the homepage. Displays the config.
        :return: The render of the settings html file
        """
        session['config'] = reload_homepage()['config']
        session['current_directory'] = os.getcwd()
        return render_template('general_settings.html')

    @app.route('/port-scanning-settings', methods=['GET'])
    def port_scanning_settings() -> str:
        """
        The route for the port scanning settings page.
        :return: The render template of the port scanning settings html file.
        """
        session['config'] = reload_homepage()['config']
        return render_template('port_scanning_settings.html', config=session['config'],
                               ports_to_scan=session['config']["ports_to_scan"])

    @app.route('/host-discovery-settings', methods=['GET'])
    def host_discovery_settings() -> str:
        """
        The route for the port scanning settings page.
        :return: The render template of the port scanning settings html file.
        """
        session['config'] = reload_homepage()['config']
        return render_template('host_discovery_settings.html', config=session['config'])

    @app.route('/advanced-settings', methods=['GET'])
    def advanced_settings() -> str:
        """
        The route for the port scanning settings page.
        :return: The render template of the port scanning settings html file.
        """
        session['config'] = reload_homepage()['config']
        return render_template('advanced_settings.html', config=session['config'])

    @app.route('/upload-subdomain-wordlist', methods=['POST'])
    def upload_subdomain_wordlist() -> Response | str:
        file = request.files['file']
        old_config = session['config']
        if file:
            old_config['ffuf_subdomain_wordlist'] = file.filename

            # update the config table
            update_config_table(old_config)

            # now we update config.json in the directory root
            update_config_json_file()

            session['config'] = reload_homepage()['config']
            return redirect(url_for('advanced_settings'))
        else:
            return error("Something went wrong trying to update the config. Please try again!",
                         url_for('advanced_settings'))

    @app.route('/upload-webpage-wordlist', methods=['POST'])
    def upload_webpage_wordlist() -> Response | str:
        file = request.files['file']
        old_config = session['config']
        if file:
            old_config['ffuf_webpage_wordlist'] = file.filename

            # update the config table
            update_config_table(old_config)

            # now we update config.json in the directory root
            update_config_json_file()

            session['config'] = reload_homepage()['config']
            return redirect(url_for('advanced_settings'))
        else:
            return error("Something went wrong trying to update the config. Please try again!",
                         url_for('advanced_settings'))

    @app.route('/upload-targets-file', methods=['POST'])
    def upload_targets_file() -> Response | str:
        """
        This is for the "Upload Targets File" button on the general settings page.
        It takes the data from the uploaded file and updates the config in the database and the config.json file in the directory root.
        :return: The redirect to the general settings page.
        """
        file = request.files['file']
        # accept .txt and no file extensions
        if file.filename.endswith('.txt') or '.' not in file.filename:
            upload_dir = os.path.join(app.root_path, 'static/temp')
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, f'{time.strftime("%d%m_%H%M%S")}_{file.filename}')
            file.save(file_path)

            with open(file_path, 'r') as f:
                targets = ', '.join([line.strip() for line in f.readlines()])

            # update targets in the database
            db = get_db()
            db.execute("UPDATE config SET targets = ?", (''.join(targets),))
            db.commit()

            # now we update config.json in the directory root
            update_config_json_file()

            # reload the page
            data = reload_homepage()
            session['config'] = data['config']
            session['files_in_directory'] = data["files_in_directory"]

            return redirect(url_for('general_settings'))

        else:
            return error("Something went wrong. Please upload a text file with one target per line!",
                         url_for('general_settings'))

    @app.route('/upload-file', methods=['POST'])
    def upload_config_file() -> Response | str:
        """
        This is for the "Upload Config File" button on the general settings page.
        It takes the data from the uploaded file and updates the config in the database and the config.json file in the directory root.
        :return: The redirect to the main/home page.
        """
        file = request.files['file']
        if file.filename.endswith('.json'):
            upload_dir = os.path.join(app.root_path, 'static/temp')
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, f'{time.strftime("%d%m_%H%M%S")}_{file.filename}')
            file.save(file_path)

            with open(file_path, 'r') as f:
                new_config = json.load(f)

            update_config_table(new_config)

            if new_config.get('config_filepath') != '':
                with open(new_config.get('config_filepath'), 'w') as file:
                    json.dump(new_config, file, indent=4)
            else:
                files_in_dir = sorted(
                    [os.path.join(os.getcwd(), file) for file in os.listdir(os.getcwd()) if file.endswith('.json')],
                    key=lambda x: (not x.endswith('.json'))
                )

                for file in files_in_dir:
                    if file.startswith(file):
                        with open(file, 'r+') as f:
                            data = json.load(f)
                            data['config_filepath'] = os.path.abspath(file)
                            f.seek(0)
                            json.dump(data, f, indent=4)
                            f.truncate()

            data = reload_homepage()
            session['config'] = data["config"]
            session['files_in_directory'] = data["files_in_directory"]

            return redirect(url_for('general_settings'))

        else:
            return error("Something went wrong. Please upload a JSON file.", url_for('general_settings'))

    @app.route('/robots.txt', methods=['GET'])
    def robots() -> Response:
        """
        The route for the robots.txt file.
        :return: The robots.txt file.
        """
        return Response(robots_string(), mimetype='text/plain')

    @app.route('/previous-scans', methods=['GET'])
    def previous_scans() -> str:
        """
        The route for viewing previous scans.
        :return: The render template of the previous scans html file.
        """
        db = get_db()
        scan_results = db.execute("SELECT * FROM scan_results").fetchall()
        results = [dict(row) for row in scan_results]
        return render_template('previous_scans.html', scan_results=results)

    @app.route('/view_single_previous_scan', methods=['POST'])
    def view_single_previous_scan() -> str:
        """
        This is for the button on the previous scans page that says "View" for each scan.
        :return: The render template of the previous scan single target html file.
        """
        scan_start_time = request.form['scan_start_time']
        db = get_db()
        result = db.execute("SELECT * FROM scan_results WHERE scan_start_time = ?", (scan_start_time,)).fetchone()
        result = dict(result)
        # we need to change the screenshot from 'output/{target}' to the location of the ss inside the flaskr directory.
        # if the screenshot isn't there then its fine, it'll just display a message.
        result['screenshot'] = f'static/screenshots/{result["target"]}.png'
        result["extra_commands_output"] = [row['command_output'] for row in db.execute(
            f"SELECT command_output FROM extra_commands WHERE scan_num = {result['scan_num']}").fetchall()]
        return render_template('previous_scan_single_target.html', result=result)

    @app.route('/add-commands', methods=['POST', 'GET'])
    def view_add_commands() -> str:
        """
        The route for the add commands page.
        If the request method is GET, it renders the add_commands page.
        If the request method is POST, it handles the form submission.
        :return: The render template of the add commands html file or a response after handling POST.
        """
        old_config = session['config']
        # if POST, take the command and append it to config['extra_commands']
        if request.method == 'POST':
            form_data = request.form
            command = form_data.get('command').strip()
            old_config['extra_commands'] = ', '.join(filter(None, [old_config['extra_commands'], command]))
            update_config_table(old_config)
            update_config_json_file()
            new_config = reload_homepage()['config']
            session['config'] = new_config
            list_of_extra_commands = new_config['extra_commands'].split(', ')
            return render_template('add_commands.html', config=session['config'], extra_commands=list_of_extra_commands)

        # if GET, render the add_commands page
        list_of_extra_commands = session['config']['extra_commands'].split(', ') if session['config'][
            'extra_commands'] else None
        return render_template('add_commands.html', config=session['config'], extra_commands=list_of_extra_commands)

    @app.route('/select-commands-file', methods=['GET'])
    def select_commands_file() -> str:
        """
        The route for selecting a commands file if no current commands file is found.
        :return: The render template of the select commands file html file.
        """
        files_in_dir = sorted(
            [os.path.join(os.getcwd(), file) for file in os.listdir(os.getcwd()) if
             file.endswith('.txt') and file != 'requirements.txt'],
            key=lambda x: (not x.endswith('.txt'))
        )
        return render_template('select_commands_file.html', files_in_directory=files_in_dir)

    @app.route('/edit-command', methods=['POST'])
    def edit_command() -> Response:
        """
        This is for the button on the add commands page that says "Edit" for each command.
        :return: The render template of the add commands html file with the command to be edited.
        """
        original_command = request.form['original_command'].strip()
        edited_command = request.form['edited_command'].strip()
        config = session['config']
        commands = config['extra_commands'].split(', ')
        for i, cmd in enumerate(commands):
            if cmd == original_command:
                commands[i] = edited_command
                break
        config['extra_commands'] = ', '.join(commands)
        update_config_table(config)
        update_config_json_file()
        new_config = reload_homepage()['config']
        session['config'] = new_config
        session['extra_commands'] = new_config['extra_commands'].split(', ')
        return redirect(url_for('view_add_commands'))

    @app.post('/update-config')
    def update_config() -> Response | str:
        """
        Update the configuration based on the settings page the request originated from.
        Redirects back to the respective settings page after updating, or shows an error if something goes wrong.
        """
        referer = request.headers.get('Referer')
        new_config = session.get('config', {}).copy()

        if not referer:
            return error("Invalid request source. Please try again!", url_for('port_scanning_settings'))

        # general
        if 'general-settings' in referer:
            new_config['targets'] = request.form.get('targets', '')
            new_config['verbose'] = 'True' if 'verbose' in request.form else 'False'
            new_config['speed'] = request.form['speed'].lower()

        # port scanning
        elif 'port-scanning-settings' in referer:
            values = request.form.to_dict()
            values['ports_to_scan'] = values.get('ports_to_scan', '').replace('\r\n', ', ')
            values['host_timeout'] = values.get('host_timeout', '').replace('\r\n', ', ')

            new_config.update({
                'aggressive_scan': 'True' if 'aggressive_scan' in values else 'False',
                'os_detection': 'True' if 'os_detection' in values else 'False'
            })
            new_config.update({k: v for k, v in values.items() if k not in ['aggressive_scan', 'os_detection']})

        # dost discovery
        elif 'host-discovery-settings' in referer:
            values = request.form.to_dict()
            new_config['ping_hosts'] = 'True' if 'ping_hosts' in values else 'False'
            new_config['ping_method'] = values.get('ping_method', '') if 'ping_hosts' in values else ''

        # advanced
        elif 'advanced-settings' in referer:
            values = request.form.to_dict()
            new_config.update({
                'disable_chatgpt_api': 'false' if 'chatgpt_api_call' in values else 'true',
                'openai_api_key': values.get('openai_api_key', ''),
                'enable_ffuf': 'True' if 'enable_ffuf' in values else 'False',
                'ffuf_redirect': 'True' if 'ffuf_redirect' in values else 'False',
                'config_filepath': values.get('config_filepath', ''),
                'chatgpt_model': values.get('chatgpt_model', ''),
                'ffuf_delay': values.get('ffuf_delay', '')
            })

        else:
            return error("Something went wrong trying to update the config. Please try again!",
                         url_for('port_scanning_settings'))

        # Update configuration and persist changes
        update_config_table(new_config)
        update_config_json_file()
        session['config'] = new_config

        return redirect(url_for(referer.split('/')[-1].replace('-', '_')))

    @app.route('/single-result')
    def single_result() -> str:
        result = session.get('scan_result_file', None)

        if not result:
            return "No result to display!"

        with open(result, 'r') as f:
            temp_file = f.read().strip() #temp_file = json file

        with open(temp_file, 'r') as f:
            parsed_json = json.load(f)

        return render_template('single_target_result.html', target=parsed_json["target"], result=parsed_json)

    @app.route('/multiple-results')
    def multiple_results() -> str:
        """
        The route for the multiple results page, which is displayed after multiple targets have been scanned.
        :return: The render template of the multiple targets html file with the json data to be displayed.
        """
        # get the results from the session
        results_file = session.get('scan_results_file')
        if not results_file:
            return "No results to display!"

        results = {}
        with open(results_file, 'r') as f:
            temp_files = [line.strip() for line in f.readlines()]

        for file_path in temp_files:
            with open(file_path, 'r') as f:
                result_data = json.load(f)
                target = result_data['target']
                results[target] = result_data

        return render_template('multiple_targets_result.html', scan_results=results)

    @app.route('/running', methods=['POST'])
    def run_ripley() -> Response | str:
        """
        When the 'run' button is pressed.
        :return: The redirect for either the multiple targets' page, or the single targets' page, depending on the config.
        """
        old_config: dict = session['config']
        check_wordlists(old_config)
        config = reload_homepage()["config"]
        unparsed_targets = config.get('targets', '').strip().split(', ')

        if not unparsed_targets:
            return error("No targets found, or there is a target error! Please check your config.",
                         url_for('general_settings'))

        full_target_list = parse_targets(unparsed_targets)
        duplicate_targets = [target for target in full_target_list if full_target_list.count(target) > 1]
        if duplicate_targets:
            return error(f"Duplicate targets found: {', '.join(set(duplicate_targets))}. Please check your target list.", url_for('general_settings'))
        
        if len(full_target_list) > 1:  # multiple targets
            start = time.time()
            psutil.cpu_percent(interval=None)
            results_file = run_on_multiple_targets(full_target_list, config)
            scan_time = round(time.time() - start, 2)
            print(f'scan took {scan_time} seconds with an average CPU usage of {psutil.cpu_percent(interval=None)}%')
            session['scan_results_file'] = results_file  # stores list of file paths in session
            return redirect(url_for('multiple_results'))
        else:  # single target
            start = time.time()
            result_file = run_on_single_target(full_target_list, config)
            print(f'scan took {time.time() - start} seconds')
            session['scan_result_file'] = result_file
            return redirect(url_for('single_result'))

    @app.route('/port-info', methods=['GET'])
    def port_info() -> str:
        """
        The route for displaying port information.
        :return: The render template of the port information html file.
        """
        port_data = get_interesting_ports()
        sorted_ports = sorted(port_data.items(), key=lambda item: len(item[1]), reverse=True)
        return render_template('port_info.html', port_data=sorted_ports)


    @app.route('/remove-extra-command', methods=['POST'])
    def remove_extra_command() -> Response:
        """
        This is for the button on the add commands page that says "Remove" for each command.
        :return: The render template of the add commands html file with the command removed.
        """
        command_to_remove = request.form['command'].strip()
        config = session['config']
        commands = config['extra_commands'].split(', ')
        for cmd in commands:
            if cmd == command_to_remove:
                commands.remove(cmd)
                break
        config['extra_commands'] = ', '.join(commands)
        update_config_table(config)
        update_config_json_file()
        new_config = reload_homepage()['config']
        session['config'] = new_config
        session['extra_commands'] = new_config['extra_commands'].split(', ')
        session['config'] = new_config
        return redirect(url_for('view_add_commands'))

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html', error_message=f"Internal server error!\n{error}",
                               redirect=url_for('general_settings')), 500

    def error(error_msg: str, full_redirect: str) -> str:
        """
        This is for the error page.
        :param error_msg: The error message to display.
        :param full_redirect: The full redirect link, eg http://localhost:5000/
        :return: The render template of the error html file.
        """
        return render_template('error.html', error_message=error_msg, redirect=full_redirect)

    @app.route('/select-config', methods=['GET'])
    def select_config() -> str:
        """
        The route for selecting a config file if no current config is found.
        :return: The render template of the select config html file.
        """
        files_in_dir = sorted(
            [os.path.join(os.getcwd(), file) for file in os.listdir(os.getcwd()) if file.endswith('.json')],
            key=lambda x: (not x.endswith('.json'))
        )

        for file in files_in_dir:
            with open(file, 'r+') as f:
                data = json.load(f)
                data['config_filepath'] = os.path.abspath(file)
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()

        return render_template('select_config.html', files_in_directory=files_in_dir)

    @app.route('/set-config', methods=['POST'])
    def set_config() -> Response:
        """
        This route sets the selected config file as the current config.
        :return: The redirect to the settings page.
        """
        selected_config = request.form['config_file']
        with open(selected_config, 'r') as f:
            config: dict = json.load(f)
        load_config_into_db(config, selected_config)
        app.config['NO_CONFIG_FOUND'] = False
        session['config'] = config
        return redirect(url_for('general_settings'))

    @app.before_request
    def check_for_config():
        """
        This function checks if the current config is set. If not, it redirects to the select config page.
        :return: The redirect to the select config page.
        """
        if request.endpoint not in ['select_config', 'set_config'] and app.config.get('NO_CONFIG_FOUND'):
            return redirect(url_for('select_config'))

    with app.app_context():
        init_db()
        config_path = get_current_config_as_full_path()
        if not config_path:
            app.config['NO_CONFIG_FOUND'] = True
        else:
            config = parse_config_file(config_path)
            load_config_into_db(config, config_path)
    return app


def get_current_config_as_full_path() -> str:
    """
    Gets the current config file path from the database.
    :return: The full path of the current config file or None if not found.
    """
    db = get_db()
    row = db.execute("SELECT config_filepath FROM config").fetchone()
    return row['config_filepath'] if row else None


def load_config_into_db(config: dict, config_filepath: str) -> None:
    """
    Uses the config dictionary to load the config into the database.
    :param config: The config dictionary.
    :param config_filepath: The full path of the config file.
    :return: None
    """
    db = get_db()
    if config:
        existing_config = db.execute("SELECT COUNT(*) FROM config").fetchone()[0]
        if existing_config == 0:
            db.execute(
                """
                INSERT INTO config (
                    targets, config_filepath, ffuf_delay,  
                    ffuf_subdomain_wordlist, ffuf_webpage_wordlist, disable_chatgpt_api, ports_to_scan, 
                    scan_type, aggressive_scan, scan_speed, os_detection, ping_hosts, ping_method, host_timeout,
                    enable_ffuf, verbose, openai_api_key, extra_commands, chatgpt_model, ffuf_redirect,
                    speed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    config.get('targets', ''),
                    config_filepath,
                    config.get('ffuf_delay', ''),
                    config.get('ffuf_subdomain_wordlist', ''),
                    config.get('ffuf_webpage_wordlist', ''),
                    config.get('disable_chatgpt_api', ''),
                    config.get('ports_to_scan', ''),
                    config.get('scan_type', ''),
                    config.get('aggressive_scan', ''),
                    config.get('scan_speed', ''),
                    config.get('os_detection', ''),
                    config.get('ping_hosts', ''),
                    config.get('ping_method', ''),
                    config.get('host_timeout', ''),
                    config.get('enable_ffuf', ''),
                    config.get('verbose', ''),
                    config.get('openai_api_key', ''),
                    config.get('extra_commands', ''),
                    config.get('chatgpt_model', ''),
                    config.get('ffuf_redirect', ''),
                    config.get('speed', '')
                )
            )
        else:
            db.execute(
                """
                UPDATE config SET
                    targets = ?,
                    config_filepath = ?,
                    ffuf_delay = ?,
                    ffuf_subdomain_wordlist = ?,
                    ffuf_webpage_wordlist = ?,
                    disable_chatgpt_api = ?,
                    ports_to_scan = ?,
                    scan_type = ?,
                    aggressive_scan = ?,
                    scan_speed = ?,
                    os_detection = ?,
                    ping_hosts = ?,
                    ping_method = ?,
                    host_timeout = ?,
                    enable_ffuf = ?,
                    verbose = ?,
                    openai_api_key = ?,
                    extra_commands = ?,
                    chatgpt_model = ?,
                    ffuf_redirect = ?,
                    speed = ?
                """,
                (
                    config.get('targets', ''),
                    config_filepath,
                    config.get('ffuf_delay', ''),
                    config.get('ffuf_subdomain_wordlist', ''),
                    config.get('ffuf_webpage_wordlist', ''),
                    config.get('disable_chatgpt_api', ''),
                    config.get('ports_to_scan', ''),
                    config.get('scan_type', ''),
                    config.get('aggressive_scan', ''),
                    config.get('scan_speed', ''),
                    config.get('os_detection', ''),
                    config.get('ping_hosts', ''),
                    config.get('ping_method', ''),
                    config.get('host_timeout', ''),
                    config.get('enable_ffuf', ''),
                    config.get('verbose', ''),
                    config.get('openai_api_key', ''),
                    config.get('extra_commands', ''),
                    config.get('chatgpt_model', ''),
                    config.get('ffuf_redirect', ''),
                    config.get('speed', '')
                )
            )
        db.commit()


# parsing logic to make sure that targets is a list of strings
def expand_ip_range(start_ip, end_ip):
    """Expand an IP range from start_ip to end_ip."""
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]


def expand_cidr(cidr):
    """Expand a CIDR range to individual IPs."""
    network = ipaddress.IPv4Network(cidr, strict=False)
    return [str(ip) for ip in network]


def parse_targets(target_list: list[str]) -> list[str]:
    """
    Parse the targets string and expand IP ranges and CIDR notations.
    :param target_list: The targets inputted by the user.
    :return: The parsed and expanded list of targets.
    """
    expanded_components = []
    for target in target_list:
        if "-" in target and re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", target):
            start_ip, end_ip = target.split("-")
            expanded_components.extend(expand_ip_range(start_ip, end_ip))
        elif "/" in target and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", target):
            expanded_components.extend(expand_cidr(target))
        else:
            expanded_components.append(target)

    return expanded_components


def reload_homepage() -> dict[str, dict[str, str] | list[str]]:
    """
    Gets the config from the database and the files from the root directory.
    The config variable stored at 'config' here, is a dict.
    The relevant files in the directory are stored at 'files_in_directory'.
    :returns: The dictionary containing the config and files in the directory.
    """
    # reload the page
    db = get_db()
    config_entries = db.execute("SELECT * FROM config").fetchall()
    config: dict[str, str] = dict(config_entries[0]) if config_entries else {}

    files_in_dir: list[str] = sorted(
        [file for file in os.listdir(os.getcwd()) if
         (file.endswith('.json') or file.endswith('.txt') or file.endswith(
             '.py')) and file != 'requirements.txt'],
        key=lambda x: (not x.endswith('.json'), not x.endswith('.txt'), not x.endswith('.py'))
    )

    return {
        'config': config,
        'files_in_directory': files_in_dir
    }


def update_config_json_file():
    """
    Updates the config.json file in the directory root with the new config from the database.
    """
    db = get_db()
    cursor = db.execute(
        """
        SELECT
            targets,
            config_filepath,
            ffuf_delay,
            ffuf_subdomain_wordlist,
            ffuf_webpage_wordlist,
            disable_chatgpt_api,
            ports_to_scan,
            scan_type,
            aggressive_scan,
            scan_speed,
            os_detection,
            ping_hosts,
            ping_method,
            host_timeout,
            enable_ffuf,
            verbose,
            openai_api_key,
            extra_commands,
            chatgpt_model,
            ffuf_redirect,
            speed
        FROM config
        """
    )
    row = cursor.fetchone()
    if row:
        config_filepath = row["config_filepath"]
        with open(config_filepath, 'r') as outfile:
            config_data = json.load(outfile)
        config_data.update({
            "targets": row["targets"],
            "config_filepath": row["config_filepath"],
            "ffuf_delay": row["ffuf_delay"],
            "ffuf_subdomain_wordlist": row["ffuf_subdomain_wordlist"],
            "ffuf_webpage_wordlist": row["ffuf_webpage_wordlist"],
            "disable_chatgpt_api": row["disable_chatgpt_api"],
            "ports_to_scan": row["ports_to_scan"],
            "scan_type": row["scan_type"],
            "aggressive_scan": row["aggressive_scan"],
            "scan_speed": row["scan_speed"],
            "os_detection": row["os_detection"],
            "ping_hosts": row["ping_hosts"],
            "ping_method": row["ping_method"],
            "host_timeout": row["host_timeout"],
            "enable_ffuf": row["enable_ffuf"],
            "verbose": row["verbose"],
            "openai_api_key": row["openai_api_key"],
            "extra_commands": row["extra_commands"],
            "chatgpt_model": row["chatgpt_model"],
            "ffuf_redirect": row["ffuf_redirect"],
            "speed": row["speed"]
        })
        with open(config_data["config_filepath"], 'w') as file:
            json.dump(config_data, file, indent=4)
            return True
    else:
        return False


def update_config_table(config: dict):
    """
    Updates the config table in the database with the new config.
    :param config: The new config as a dictionary.
    """
    db = get_db()
    db.execute(
        """
        UPDATE config SET 
            targets = ?,
            config_filepath = ?, 
            ffuf_delay = ?, 
            ffuf_subdomain_wordlist = ?, 
            ffuf_webpage_wordlist = ?, 
            disable_chatgpt_api = ?,
            ports_to_scan = ?,
            scan_type = ?,
            aggressive_scan = ?,
            scan_speed = ?,
            os_detection = ?,
            ping_hosts = ?,
            ping_method = ?,
            host_timeout = ?,
            enable_ffuf = ?,
            verbose = ?,
            openai_api_key = ?,
            extra_commands = ?,
            chatgpt_model = ?,
            ffuf_redirect = ?,
            speed = ?
        """,
        (
            config.get('targets', ''),
            config.get('config_filepath', ''),
            config.get('ffuf_delay', ''),
            config.get('ffuf_subdomain_wordlist', ''),
            config.get('ffuf_webpage_wordlist', ''),
            config.get('disable_chatgpt_api', ''),
            config.get('ports_to_scan', ''),
            config.get('scan_type', ''),
            config.get('aggressive_scan', ''),
            config.get('scan_speed', ''),
            config.get('os_detection', ''),
            config.get('ping_hosts', ''),
            config.get('ping_method', ''),
            config.get('host_timeout', ''),
            config.get('enable_ffuf', ''),
            config.get('verbose', ''),
            config.get('openai_api_key', ''),
            config.get('extra_commands', ''),
            config.get('chatgpt_model', ''),
            config.get('ffuf_redirect', ''),
            config.get('speed', '')
        )
    )
    db.commit()


def check_wordlists(config: dict):
    """
    Checks if the ffuf wordlists are set in the config. If they aren't it then checks if the defaults have been downloaded
    and if they have, it then sets them in the config. If they haven't, aka its the first time running, then it downloads them
    and sets them in the config.
    :param config: The configuration file as a dictionary.
    :return: None
    """

    # if there are no wordlists, download them and set them in the config
    def check_subdomain(subdomain_wordlist: str):
        """
        Check if the subdomain wordlist is set in the config. If it isn't, it then checks if the default has been downloaded
        :param subdomain_wordlist: The subdomain wordlist in the config.
        :return:
        """
        if not subdomain_wordlist:
            # check if wordlist exists already in proj root
            db = get_db()
            for file in os.listdir():
                if file == 'dnspod-top2000-sub-domains.txt':
                    # the file has been downloaded already but not set in the config!
                    db.execute("UPDATE config SET ffuf_subdomain_wordlist = 'dnspod-top2000-sub-domains.txt'")
                    db.commit()
                    update_config_json_file()
                    return
            else:
                # get suitable wordlist from git if not found
                url = 'https://raw.githubusercontent.com/DNSPod/oh-my-free-data/master/src/dnspod-top2000-sub-domains.txt'
                t = run_command_with_output_after(f'curl -o dnspod-top2000-sub-domains.txt {url}', config['verbose'])
                if t.returncode == 0:
                    db.execute("UPDATE config SET ffuf_subdomain_wordlist = 'dnspod-top2000-sub-domains.txt'")
                    db.commit()
                    update_config_json_file()
                    return

    def check_directory(directory_wordlist: str):
        """
        Check if the directory wordlist is set in the config. If it isn't, it then checks if the default has been downloaded
        :param directory_wordlist: The directory wordlist in the config.
        :return:
        """
        if not directory_wordlist:
            db = get_db()
            # check if wordlist exists already in proj root
            for file in os.listdir():
                if file == 'Directories_Common.wordlist':
                    db.execute("UPDATE config SET ffuf_webpage_wordlist = 'Directories_Common.wordlist'")
                    db.commit()
                    update_config_json_file()
                    return
            else:
                # get suitable wordlist from git if not found
                url = 'https://raw.githubusercontent.com/emadshanab/WordLists-20111129/master/Directories_Common.wordlist'
                t = run_command_with_output_after(f'curl -o Directories_Common.wordlist {url}', config['verbose'])
                if t.returncode == 0:
                    db.execute("UPDATE config SET ffuf_webpage_wordlist = 'Directories_Common.wordlist'")
                    db.commit()
                    update_config_json_file()
                    return

    subdomain_wordlist = config['ffuf_subdomain_wordlist']
    check_subdomain(subdomain_wordlist)
    directory_wordlist = config['ffuf_webpage_wordlist']
    check_directory(directory_wordlist)


def get_interesting_ports() -> dict:
    """
    Looks in flaskr/static/temp for all nmap xml outputs and parses them looking for ports.
    :returns: a dictionary where keys are port numbers and values are lists of hosts with those ports open.
    """
    port_dict = {}
    xml_files = [f for f in os.listdir('flaskr/static/temp') if f.endswith('.xml') and f.startswith('nmap')]

    for xml_file in xml_files:
        report = NmapParser.parse_fromfile(f'flaskr/static/temp/{xml_file}')
        for host in report.hosts:
            host_ip = host.address
            hostname = host.hostnames[0] if host.hostnames else ""
            for service in host.services:
                if service.open():
                    port_number = service.port
                    if port_number not in port_dict:
                        port_dict[port_number] = []
                    port_dict[port_number].append(host_ip)
                    port_dict[port_number].append(hostname)

    return port_dict
