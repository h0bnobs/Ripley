import json
import os

from flask import Flask, render_template, request, redirect, url_for

from flaskr.db import get_db, init_db
from ripley_cli import get_target_list
from flaskr.run_tool_for_gui import run_on_multiple_targets, run_on_single_target
from scripts.utils import parse_config_file

# flask --app flaskr init-db
# flask --app flaskr run --debug

# todo this is hardcoded
config = parse_config_file("config.json")


def create_app(test_config=None):
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

        # Route for displaying the configuration and the "Run Ripley" button

    @app.route('/')
    def index():
        db = get_db()
        s = f''
        config_entries = db.execute("SELECT * FROM config").fetchall()
        results = [dict(entry) for entry in config_entries]  # Convert rows to dict for easier display
        print(results)
        return render_template('index.html', results=results)

    @app.route('/update-config', methods=['POST'])
    def update_config():
        """
        This is for the button on the main/home page called "Update Config". What this does is it takes the data from
        the textarea with the id="config" from index.html, and it uses it to update the config in the database.
        Then it reloads the main/home page with this updated config.
        """
        new_config = json.loads(request.form['config'])
        db = get_db()
        db.execute(
            "UPDATE config SET single_target = ?, multiple_targets = ?, targets_file = ?, nmap_parameters = ?, config_filepath = ?",
            (new_config['single_target'],
             new_config['multiple_targets'],
             new_config['targets_file'],
             new_config['nmap_parameters'],
             new_config['config_filepath'])
        )
        db.commit()
        config_entries = db.execute("SELECT * FROM config").fetchall()
        return redirect(url_for('index'))

    # Route for the "Run Ripley" button
    @app.route('/running', methods=['POST'])
    def run_ripley():
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
            result = run_on_multiple_targets(target_list, config)
        elif len(target_list) == 1:
            result = run_on_single_target(target_list, config)
        else:
            raise Exception("Target list empty!")

        # result = run_nmap(target_list[0], "-Pn")
        # return ""
        return f"<pre>{result}</pre>"

    from . import db
    db.init_app(app)
    with app.app_context():
        init_db()
        load_config_into_db()
    return app


def load_config_into_db():
    config_filepath = ""
    for file in os.listdir():
        if file.endswith(".json") and file.startswith("config"):
            config_filepath = file
            break

    db = get_db()
    if config:
        # Insert into the config table
        db.execute(
            "INSERT INTO config (single_target, multiple_targets, targets_file, nmap_parameters, config_filepath) VALUES (?, ?, ?, ?, ?)",
            (config.get('single_target', ''),
             config.get('multiple_targets', ''),
             config.get('targets_file', ''),
             config.get('nmap_parameters', ''),
             config_filepath)
        )
        db.commit()
