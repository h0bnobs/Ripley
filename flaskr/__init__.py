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

    @app.route('/')
    def settings() -> str:
        """
        The route for the homepage. Displays the config.
        :return: The render of the settings html file
        """
        db = get_db()
        config_entries = db.execute("SELECT * FROM config").fetchall()
        config = [dict(entry) for entry in config_entries]

        extra_commands_filename = config[0].get('extra_commands_file')
        extra_commands = None

        if extra_commands_filename:
            try:
                with open(extra_commands_filename) as f:
                    extra_commands = f.readlines()
            except FileNotFoundError:
                extra_commands = None

        files_in_dir = sorted(
            [file for file in os.listdir(os.getcwd()) if
             (file.endswith('.json') or file.endswith('.txt') or file.endswith('.py')) and file != 'requirements.txt'],
            key=lambda x: (not x.endswith('.json'), not x.endswith('.txt'), not x.endswith('.py'))
        )

        return render_template('settings.html', results=config, current_directory=os.getcwd(),
                               files_in_directory=files_in_dir, extra_commands=extra_commands)

    @app.route('/upload-file', methods=['POST'])
    def check_file():
        """
        This is for the "Upload Files" button on the main/home page. It checks if the file is a valid file, and if it is,
        it writes the contents of the file to a temporary file in the static/temp directory and updates the config.
        :return: The redirect to the main/home page.
        """
        file = request.files['file']
        if file.filename.endswith('.json'):
            upload_dir = os.path.join(app.root_path, 'uploaded_configs')
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, f'{time.strftime("%d%m_%H%M%S")}_{file.filename}')
            file.save(file_path)

            with open(file_path, 'r') as f:
                new_config = json.load(f)

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
                    disable_chatgpt_api = ?
                """,
                (
                    new_config.get('targets', ''),
                    new_config.get('nmap_parameters', ''),
                    new_config.get('config_filepath', ''),
                    new_config.get('ffuf_delay', ''),
                    new_config.get('extra_commands_file', ''),
                    new_config.get('ffuf_subdomain_wordlist', ''),
                    new_config.get('ffuf_webpage_wordlist', ''),
                    new_config.get('disable_chatgpt_api', '')
                )
            )
            db.commit()

            # update current_config table
            t = new_config.get('config_filepath').split('/')
            db.execute(
                "UPDATE current_config SET full_path = ?, filename = ?",
                (new_config.get('config_filepath'), t[-1])
            )
            db.commit()

            with open(new_config.get('config_filepath'), 'w') as file:
                json.dump(new_config, file, indent=4)

            config_entries = db.execute("SELECT * FROM config").fetchall()
            config = [dict(entry) for entry in config_entries]

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

            return render_template('settings.html', results=config, current_directory=os.getcwd(),
                                   files_in_directory=files_in_dir, extra_commands=extra_commands)

        else:
            return error("Something went wrong. Please upload a JSON file.", url_for('settings'))

    @app.route('/view-targets-file')
    def view_targets_file() -> tuple[str, int] | Response:
        """
        Serves the targets file for viewing in the browser.
        :return: The content of the targets file.
        """
        targets_filepath = request.args.get('filepath')
        if not targets_filepath:
            return "No targets file specified!", 400

        try:
            with open(targets_filepath, 'r') as file:
                content = file.read()
            return Response(content, mimetype='text/plain')
        except FileNotFoundError:
            return "Targets file not found!", 404

    @app.route('/robots.txt')
    def robots() -> Response:
        """
        The route for the robots.txt file.
        :return: The robots.txt file.
        """
        return Response(robots_string(), mimetype='text/plain')

    @app.route('/previous-scans')
    def previous_scans() -> str:
        """
        The route for viewing previous scans.
        :return: The render template of the previous scans html file.
        """
        db = get_db()
        scan_results = db.execute("SELECT * FROM scan_results").fetchall()
        results = [dict(row) for row in scan_results]
        return render_template('previous_scans.html', results=results)

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
                url_for('settings'))

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
    def update_config() -> Response:
        """
        This is for the button on the main/home page called "Update Config". What this does is it takes the data from
        the textarea with the id="config" from settings.html, and it uses it to update the config in the database and the config.json file in the directory root.
        Then it reloads the main/home page with this updated config.
        :return: The homepage again with the updated config.
        """
        new_config = json.loads(request.form['config'])
        targets = request.form['targets']

        # first update the config table
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
                disable_chatgpt_api = ?
            """,
            (
                targets,
                new_config['nmap_parameters'],
                new_config['config_filepath'],
                new_config['ffuf_delay'],
                new_config['extra_commands_file'],
                new_config['ffuf_subdomain_wordlist'],
                new_config['ffuf_webpage_wordlist'],
                new_config['disable_chatgpt_api']
            )
        )
        db.commit()

        # then we update the current_config table, assuming that the config file is in the project root.
        t = new_config['config_filepath'].split('/')
        db.execute(
            "UPDATE current_config SET full_path = ?, filename = ?",
            (new_config['config_filepath'], t[-1])
        )
        db.commit()

        # now we update config.json in the directory root
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
                disable_chatgpt_api
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
                "disable_chatgpt_api": row["disable_chatgpt_api"]
            })
            with open(config_data["config_filepath"], 'w') as file:
                json.dump(config_data, file, indent=4)
        else:
            print("No data found in the config table.")

        return redirect(url_for('settings'))

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

        return render_template('multiple_targets_result.html', results=results)

    @app.route('/running', methods=['POST'])
    def run_ripley() -> Response | str:
        """
        When the 'run' button is pressed.
        :return: The redirect for either the multiple targets' page, or the single targets' page, depending on the config.
        """
        config = json.loads(request.form['running'])
        unparsed_targets = config.get('targets', '').strip().split(', ')

        if not unparsed_targets:
            return error("No targets found, or there is a target error! Please check your config.", url_for('settings'))

        if config.get("extra_commands_file"):
            with open(config.get("extra_commands_file"), 'r') as f:
                if not f.readlines():
                    return error(
                        f'Extra commands file option in populated in config but, the file {config.get("extra_commands_file")} is empty!',
                        url_for('settings'))

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
    def remove_extra_command() -> str:
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
        return render_template('add_commands.html', config=config, extra_commands=commands)

    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html', error_message="Internal server error!", redirect=url_for('settings')), 500

    def error(error_msg: str, full_redirect: str) -> str:
        """
        This is for the error page.
        :param error_msg: The error message to display.
        :param full_redirect: The full redirect link, eg http://localhost:5000/
        :return: The render template of the error html file.
        """
        return render_template('error.html', error_message=error_msg, redirect=full_redirect)

    @app.route('/select-config')
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
        return redirect(url_for('settings'))

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
                ffuf_subdomain_wordlist, ffuf_webpage_wordlist, disable_chatgpt_api
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
    :param targets_string: The targets inputted by the user.
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
