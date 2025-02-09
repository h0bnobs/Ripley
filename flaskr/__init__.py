"""
This script initializes and configures a Flask application for running various network scanning tools.

It sets up the Flask app, configures routes for updating and displaying configurations, running scans on targets,
and displaying scan results. It also ensures the database is initialized and provides utility functions for
handling scan results and configurations.

Modules:
    flaskr.db: Manages the SQLite database connection and initialization.
    flaskr.run_tool_for_gui: Contains functions to run network scanning tools on single or multiple targets.
    scripts.utils: Provides utility functions for parsing configuration files and displaying banners.
"""
import json, os, time, re, ipaddress
from flask import Flask, render_template, request, redirect, url_for, session, Response
from flaskr.db import get_db, init_db
from flaskr.run_tool_for_gui import run_on_multiple_targets, run_on_single_target
from scripts.utils import parse_config_file, robots_string


# flask --app flaskr init-db
# flask --app flaskr run --debug

def create_app(test_config=None) -> Flask:
    """
    Create and configure the Flask application.

    This function initializes the Flask app with necessary configurations, routes, and database connections.
    It also sets up the instance folder, applies the configuration (from a provided test config or the instance config),
    and ensures the database is initialized. Routes for updating and displaying configurations, running scans on targets,
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

    @app.route('/general-settings', methods=['GET'])
    def general_settings() -> str:
        """
        The route for the homepage. Displays the config.
        :return: The render of the settings html file
        """
        data = reload_homepage()
        session['config'] = data["config"]
        session['files_in_directory'] = data["files_in_directory"]
        session['extra_commands'] = data["extra_commands"]
        session['current_directory'] = os.getcwd()
        print(session['config'])
        return render_template('general_settings.html')

    @app.route('/port-scanning-settings', methods=['GET'])
    def port_scanning_settings() -> str:
        """
        The route for the port scanning settings page.
        :return: The render template of the port scanning settings html file.
        """
        db = get_db()
        c = db.execute("SELECT * FROM config").fetchall()
        config = [dict(entry) for entry in c][0]
        session['config'] = config
        return render_template('port_scanning_settings.html', config=config, ports_to_scan=config["ports_to_scan"])

    @app.route('/host-discovery-settings', methods=['GET'])
    def host_discovery_settings() -> str:
        """
        The route for the port scanning settings page.
        :return: The render template of the port scanning settings html file.
        """
        return render_template('host_discovery_settings.html')

    @app.route('/advanced-settings', methods=['GET'])
    def advanced_settings() -> str:
        """
        The route for the port scanning settings page.
        :return: The render template of the port scanning settings html file.
        """
        return render_template('advanced_settings.html')

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
            session['config'] = data["config"]
            session['files_in_directory'] = data["files_in_directory"]
            session['extra_commands'] = data["extra_commands"]

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

            # update current_config table
            db = get_db()
            t = new_config.get('config_filepath').split('/')
            db.execute(
                "UPDATE current_config SET full_path = ?, filename = ?",
                (new_config.get('config_filepath'), t[-1])
            )
            db.commit()

            with open(new_config.get('config_filepath'), 'w') as file:
                json.dump(new_config, file, indent=4)

            data = reload_homepage()
            session['config'] = data["config"]
            session['files_in_directory'] = data["files_in_directory"]
            session['extra_commands'] = data["extra_commands"]

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
        db = get_db()
        config_entries = db.execute("SELECT * FROM config").fetchall()
        config = [dict(entry) for entry in config_entries]
        extra_commands_filename = config[0]['extra_commands_file']
        # if POST, handle the form submission
        if request.method == 'POST':
            form_data = request.form
            command = form_data.get('command').strip()
            with open(extra_commands_filename, 'a') as f:
                f.write(f'{command}\n')
                # print(command, file=f)
            with open(extra_commands_filename, 'r') as f:
                extra_commands = f.readlines()
            return render_template('add_commands.html', config=config, extra_commands=extra_commands,
                                   commands_file=extra_commands_filename)

        # if GET, render the page with config and any commands that have already been added
        try:
            with open(extra_commands_filename, 'r') as f:
                extra_commands = f.readlines()
                return render_template('add_commands.html', config=config, extra_commands=extra_commands,
                                       commands_file=extra_commands_filename)
        except FileNotFoundError:
            return error(
                f"No extra commands file found in {config[0]['config_filepath']}. Please review your config and try again!",
                url_for('general_settings'))

    @app.route('/edit-command', methods=['POST'])
    def edit_command():
        """
        This is for the button on the add commands page that says "Edit" for each command.
        :return: The render template of the edit command html file with the command to be edited.
        """
        original_command = request.form['original_command'].strip()
        edited_command = request.form['edited_command']
        line_number = int(request.form['line_number'])

        db = get_db()
        config = db.execute("SELECT * FROM config").fetchall()
        config = [dict(entry) for entry in config]

        with open(config[0]['extra_commands_file'], 'r') as f:
            current_commands = f.read().splitlines()

        if 0 <= line_number < len(current_commands) and current_commands[line_number] == original_command:
            current_commands[line_number] = edited_command

        with open(config[0]['extra_commands_file'], 'w') as f:
            for c in current_commands:
                f.write(f'{c}\n')

        return redirect(url_for('view_add_commands'))

    @app.route('/update-config', methods=['POST'])
    def update_config() -> Response | str:
        """
        This endpoint is for updating the config. It can be called from the settings pages (general, port scanning, etc.).
        :return: A redirect to the settings page from which the request was made, or an error page if something went wrong.
        """
        referer = request.headers.get('Referer')

        # if the request is coming from /general-settings:
        if referer and 'general-settings' in referer:
            new_config = json.loads(request.form['config'])
            targets = request.form['targets']
            new_config["targets"] = targets
            # first update the config table
            update_config_table(new_config)

            # then we update the current_config table, assuming that the config file is in the project root
            t = new_config['config_filepath'].split('/')
            db = get_db()
            db.execute(
                "UPDATE current_config SET full_path = ?, filename = ?",
                (new_config['config_filepath'], t[-1])
            )
            db.commit()

            # now we update config.json in the directory root
            update_config_json_file()

            # get the relevant data for the homepage and set the session variables for the general settings page
            data = reload_homepage()
            session['config'] = data["config"]
            session['files_in_directory'] = data["files_in_directory"]
            session['extra_commands'] = data["extra_commands"]

            return redirect(url_for('general_settings'))

        #if the request is coming from /port-scanning-settings:
        elif referer and 'port-scanning-settings' in referer:
            values = request.form.to_dict()  # form data

            # parse the ports to scan
            if 'ports_to_scan' in values:
                if '\r\n' in values['ports_to_scan']:
                    values['ports_to_scan'] = values['ports_to_scan'].replace('\r\n', ', ')

            old_config = session['config']  # old config from when save was pressed

            # aggressive_scan is either True or nothing when its coming in here from the form.
            if 'aggressive_scan' in values:
                old_config['aggressive_scan'] = 'True'
            elif 'aggressive_scan' not in values:
                old_config['aggressive_scan'] = 'False'

            if 'os_detection' in values:
                old_config['os_detection'] = 'True'
            elif 'os_detection' not in values:
                old_config['os_detection'] = 'False'

            for value in values:  # update the old config with the new values
                if value != 'aggressive_scan':
                    old_config[value] = values[value]

            # update the config table
            update_config_table(old_config)

            # now we update config.json in the directory root
            update_config_json_file()

            # get the relevant data for the port scanning page and set the session variables
            db = get_db()
            c = db.execute("SELECT * FROM config").fetchall()
            config = [dict(entry) for entry in c][0]
            session['config'] = config
            session['ports_to_scan'] = config["ports_to_scan"]
            return redirect(url_for('port_scanning_settings'))

        else:
            return error("Something went wrong trying to update the config. Please try again!",
                         url_for('port_scanning_settings'))

    @app.route('/single-result')
    def single_result() -> str:
        result = session.get('scan_result_file', None)

        if not result:
            return "No result to display!"

        with open(result, 'r') as f:
            parsed_json = json.load(f)

        return render_template('single_target_result.html', target=parsed_json["target"], result=parsed_json)

    @app.route('/multiple-results')
    def multiple_results() -> str:
        """
        The route for the multiple results page, which is displayed after multiple targets have been scanned.
        :return: The render template of the multiple targets html file with the json data to be displayed.
        """
        # get the results from the session
        results_files = session.get('scan_results_files')
        if not results_files:
            return "No results to display!"

        results = {}
        for file_path in results_files:
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
        config = session.get('config')[0]
        unparsed_targets = config.get('targets', '').strip().split(', ')

        if not unparsed_targets:
            return error("No targets found, or there is a target error! Please check your config.",
                         url_for('general_settings'))

        if config.get("extra_commands_file"):
            with open(config.get("extra_commands_file"), 'r') as f:
                if not f.readlines():
                    return error(
                        f'Extra commands file option in populated in config but, the file {config.get("extra_commands_file")} is empty!',
                        url_for('general_settings'))

        full_target_list = parse_targets(unparsed_targets)

        if len(full_target_list) > 1:  # multiple targets
            start = time.time()
            results_files = run_on_multiple_targets(full_target_list, config)
            print(f'########### {time.time() - start} seconds ###########')
            session['scan_results_files'] = results_files  # stores list of file paths in session
            return redirect(url_for('multiple_results'))
        else:  # single target
            result_file = run_on_single_target(full_target_list, config)
            session['scan_result_file'] = result_file
            return redirect(url_for('single_result'))

    @app.route('/remove-extra-command', methods=['POST'])
    def remove_extra_command() -> Response:
        """
        This is for the button on the add commands page that says "Remove" for each command.
        :return: The render template of the add commands html file with the command removed.
        """
        command_to_remove = request.form['command'].strip()
        db = get_db()
        config = db.execute("SELECT * FROM config").fetchall()
        config = [dict(entry) for entry in config]
        extra_commands_filename = config[0]['extra_commands_file']
        with open(extra_commands_filename, 'r') as f:
            commands = f.readlines()
        commands = [cmd for cmd in commands if cmd.strip() != command_to_remove]
        with open(extra_commands_filename, 'w') as f:
            f.writelines(commands)
        session['extra_commands'] = commands
        session['config'] = config
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
        return render_template('select_config.html', files_in_directory=files_in_dir)

    @app.route('/set-config', methods=['POST'])
    def set_config() -> Response:
        """
        This route sets the selected config file as the current config.
        :return: The redirect to the settings page.
        """
        selected_config = request.form['config_file']
        filename = os.path.basename(selected_config)
        db = get_db()
        db.execute("INSERT INTO current_config (full_path, filename) VALUES (?, ?)", (selected_config, filename))
        db.commit()
        config = parse_config_file(selected_config)
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
    row = db.execute("SELECT full_path FROM current_config").fetchone()
    return row['full_path'] if row else None


def load_config_into_db(config: dict, config_filepath: str) -> None:
    """
    Uses the config dictionary to load the config into the database.
    :param config: The config dictionary.
    :param config_filepath: The full path of the config file.
    :return: None
    """
    db = get_db()
    if config:
        db.execute(
            """
            INSERT INTO config (
                targets, nmap_parameters, config_filepath, ffuf_delay, extra_commands_file, 
                ffuf_subdomain_wordlist, ffuf_webpage_wordlist, disable_chatgpt_api, ports_to_scan, 
                scan_type, aggressive_scan, scan_speed, os_detection
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                config.get('targets', ''),
                config.get('nmap_parameters', ''),
                config_filepath,
                config.get('ffuf_delay', ''),
                config.get('extra_commands_file', ''),
                config.get('ffuf_subdomain_wordlist', ''),
                config.get('ffuf_webpage_wordlist', ''),
                config.get('disable_chatgpt_api', ''),
                config.get('ports_to_scan', ''),
                config.get('scan_type', ''),
                config.get('aggressive_scan', ''),
                config.get('scan_speed', ''),
                config.get('os_detection', '')
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


def reload_homepage() -> dict:
    """
    Gets the config from the database and returns it as a dictionary. The config variable stored at 'config' here, is a list with 1 element which is a dict.
    The relevant files in the directory are stored at 'files_in_directory' and the extra commands are stored at 'extra_commands'.
    :returns: The dictionary containing the config, files in the directory, and extra commands.
    """
    # reload the page
    db = get_db()
    config_entries = db.execute("SELECT * FROM config").fetchall()
    config = [dict(entry) for entry in config_entries]  # list containing one element which is a dict.

    extra_commands_filename = config[0].get('extra_commands_file')
    extra_commands = None

    if extra_commands_filename:
        with open(extra_commands_filename) as f:
            extra_commands = f.readlines()

    files_in_dir = sorted(
        [file for file in os.listdir(os.getcwd()) if
         (file.endswith('.json') or file.endswith('.txt') or file.endswith(
             '.py')) and file != 'requirements.txt'],
        key=lambda x: (not x.endswith('.json'), not x.endswith('.txt'), not x.endswith('.py'))
    )

    return {
        'config': config,
        'files_in_directory': files_in_dir,
        'extra_commands': extra_commands
    }


def update_config_json_file():
    db = get_db()
    cursor = db.execute(
        """
        SELECT
            targets,
            nmap_parameters,
            config_filepath,
            ffuf_delay,
            extra_commands_file,
            ffuf_subdomain_wordlist,
            ffuf_webpage_wordlist,
            disable_chatgpt_api,
            ports_to_scan,
            scan_type,
            aggressive_scan,
            scan_speed,
            os_detection
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
            "nmap_parameters": row["nmap_parameters"],
            "config_filepath": row["config_filepath"],
            "ffuf_delay": row["ffuf_delay"],
            "extra_commands_file": row["extra_commands_file"],
            "ffuf_subdomain_wordlist": row["ffuf_subdomain_wordlist"],
            "ffuf_webpage_wordlist": row["ffuf_webpage_wordlist"],
            "disable_chatgpt_api": row["disable_chatgpt_api"],
            "ports_to_scan": row["ports_to_scan"],
            "scan_type": row["scan_type"],
            "aggressive_scan": row["aggressive_scan"],
            "scan_speed": row["scan_speed"],
            "os_detection": row["os_detection"]
        })
        with open(config_data["config_filepath"], 'w') as file:
            json.dump(config_data, file, indent=4)
            return True
    else:
        return False


def update_config_table(config):
    if isinstance(config, dict):
        db = get_db()
        db.execute(
            """
            UPDATE config SET 
                targets = ?,
                nmap_parameters = ?, 
                config_filepath = ?, 
                ffuf_delay = ?, 
                extra_commands_file = ?, 
                ffuf_subdomain_wordlist = ?, 
                ffuf_webpage_wordlist = ?, 
                disable_chatgpt_api = ?,
                ports_to_scan = ?,
                scan_type = ?,
                aggressive_scan = ?,
                scan_speed = ?,
                os_detection = ?
            """,
            (
                config.get('targets', ''),
                config.get('nmap_parameters', ''),
                config.get('config_filepath', ''),
                config.get('ffuf_delay', ''),
                config.get('extra_commands_file', ''),
                config.get('ffuf_subdomain_wordlist', ''),
                config.get('ffuf_webpage_wordlist', ''),
                config.get('disable_chatgpt_api', ''),
                config.get('ports_to_scan', ''),
                config.get('scan_type', ''),
                config.get('aggressive_scan', ''),
                config.get('scan_speed', ''),
                config.get('os_detection', '')
            )
        )
        db.commit()
