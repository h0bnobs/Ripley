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
import json
import os
import time

from flask import Flask, render_template, request, redirect, url_for, session, Response

from flaskr.db import get_db, init_db
from ripley_cli import get_target_list
from flaskr.run_tool_for_gui import run_on_multiple_targets, run_on_single_target
from scripts.utils import parse_config_file, robots_string

# flask --app flaskr init-db
# flask --app flaskr run --debug

# todo this is hardcoded
config = parse_config_file("config.json")


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

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route('/')
    def index() -> str:
        """
        The route for the homepage. Displays the config.
        :return: The render of the index html file
        """
        db = get_db()
        config_entries = db.execute("SELECT * FROM config").fetchall()
        config = [dict(entry) for entry in config_entries]
        targets = config[0]['single_target'] or open(config[0]['targets_file']).readlines() if config[0]['targets_file'] else None
        print(config)
        with open('flaskr/static/temp/extra_commands.txt', 'r') as f:
            extra_commands = f.readlines()
        if targets is None:
            return render_template('index.html', results=config, extra_commands=extra_commands)
        else:
            return render_template('index.html', results=config, targets=targets, extra_commands=extra_commands)

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
        if request.method == 'POST':
            form_data = request.form
            command = form_data.get('command').strip()
            with open('flaskr/static/temp/extra_commands.txt', 'a') as f:
                f.write(f'{command}\n')
                #print(command, file=f)
            with open('flaskr/static/temp/extra_commands.txt', 'r') as f:
                extra_commands = f.readlines()
            return render_template('add_commands.html', config=config, extra_commands=extra_commands)

        with open('flaskr/static/temp/extra_commands.txt', 'r') as f:
            extra_commands = f.readlines()
        #if GET, render the page with config and any commands that have already been added
        return render_template('add_commands.html', config=config, extra_commands=extra_commands)

    @app.route('/update-config', methods=['POST'])
    def update_config() -> Response:
        """
        This is for the button on the main/home page called "Update Config". What this does is it takes the data from
        the textarea with the id="config" from index.html, and it uses it to update the config in the database and the config.json file in the directory root.
        Then it reloads the main/home page with this updated config.
        :return: The homepage again with the updated config.
        """
        new_config = json.loads(request.form['config'])
        db = get_db()
        db.execute(
            "UPDATE config SET single_target = ?, multiple_targets = ?, targets_file = ?, nmap_parameters = ?, config_filepath = ?, ffuf_delay = ?",
            (new_config['single_target'],
             new_config['multiple_targets'],
             new_config['targets_file'],
             new_config['nmap_parameters'],
             new_config['config_filepath'],
             new_config['ffuf_delay'])
        )
        db.commit()

        # now we update config.json in the directory root
        cursor = db.execute(
            "SELECT single_target, multiple_targets, targets_file, nmap_parameters, config_filepath, ffuf_delay FROM config")
        row = cursor.fetchone()
        if row:
            config_filepath = row["config_filepath"]
            with open(config_filepath, 'r') as outfile:
                config_data = json.load(outfile)
            config_data["single_target"] = row["single_target"]
            config_data["multiple_targets"] = row["multiple_targets"]
            config_data["targets_file"] = row["targets_file"]
            config_data["nmap_parameters"] = row["nmap_parameters"]
            config_data["config_filepath"] = row["config_filepath"]
            config_data["ffuf_delay"] = row["ffuf_delay"]
            with open('config.json', 'w') as file:
                json.dump(config_data, file, indent=4)
        else:
            print("No data found in the config table.")

        return redirect(url_for('index'))

    @app.route('/single-result')
    def single_result() -> str:
        """
        The route for the single results page, which is displayed after a single target has been scanned.
        :return: The render template of the single targets html file with the json data to be displayed.
        """
        # get the results from the session
        result = session.get('scan_result_file', None)

        if not result:
            return "No results to display!"

        with open(result, 'r') as f:
            parsed_json = json.load(f)
        print("")

        return render_template('single_target_result.html', target=parsed_json['target'], result=parsed_json)

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
    def run_ripley() -> Response:
        """
        When the 'run' button is pressed.
        :return: The redirect for either the multiple targets' page, or the single targets' page, depending on the config.
        """
        config = json.loads(request.form['running'])
        single_target = config.get("single_target", "").strip()
        multiple_targets = config.get("multiple_targets", [])
        targets_file = config.get("targets_file", "").strip()

        target_count = sum([bool(single_target), bool(multiple_targets), bool(targets_file)])
        if target_count != 1:
            raise Exception("You must specify exactly one of 'single_target', 'multiple_targets', or 'targets_file'.")

        target_list = get_target_list(single_target, multiple_targets, targets_file)

        # once target_list is filled, either run_on_multiple_targets or run_on_single_target is called based on the length
        if len(target_list) > 1:
            start = time.time()
            results_files = run_on_multiple_targets(target_list, config)
            print(f'########### {time.time() - start} seconds ###########')
            session['scan_results_files'] = results_files  # stores list of file paths in session
            return redirect(url_for('multiple_results'))
        elif len(target_list) == 1:
            result_file = run_on_single_target(target_list, config)
            session['scan_result_file'] = result_file
            return redirect(url_for('single_result'))
        else:
            raise Exception("Target list empty!")

    from . import db
    db.init_app(app)
    with app.app_context():
        init_db()
        load_config_into_db()
    return app


def load_config_into_db() -> None:
    """
    Gets the config from the root directory and puts it into the config table in the db.
    """
    config_filepath = ""
    for file in os.listdir():
        if file.endswith(".json") and file.startswith("config"):
            config_filepath = file
            break

    db = get_db()
    if config:
        db.execute(
            "INSERT INTO config (single_target, multiple_targets, targets_file, nmap_parameters, config_filepath, ffuf_delay) VALUES (?, ?, ?, ?, ?, ?)",
            (config.get('single_target', ''),
             config.get('multiple_targets', ''),
             config.get('targets_file', ''),
             config.get('nmap_parameters', ''),
             config_filepath,
             config.get('ffuf_delay', ''))
        )
        db.commit()
