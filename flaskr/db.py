"""
Initializes and manages the sqlite database connection.
provides functions for connecting to and closing the database, initializing the database with
a schema, and adding a CLI command to set up the database.
"""

import sqlite3
from typing import Any

import click
from flask import current_app, g, Flask


def get_db() -> sqlite3.Connection:
    """
    Returns the SQLite database connection for the current Flask application context.
    :return: The SQLite database connection for the current Flask application context.
    """
    g.db = sqlite3.connect(
        current_app.config['DATABASE'],
        detect_types=sqlite3.PARSE_DECLTYPES
    )
    g.db.row_factory = sqlite3.Row

    return g.db


def close_db(e: Any =None) -> None:
    """
    Closes the SQLite database connection for the current Flask application context, if open.

    This function is registered to run at the end of each request to ensure the connection
    is properly closed and resources are released.

    :Args: e (Optional[Exception]): An optional exception that may be passed if an error occurred during request handling, though it is not used in this function.
    """
    db = g.pop('db', None)

    if db is not None:
        db.close()


def init_db() -> None:
    """
    Initializes the SQLite database by executing the SQL statements in 'flaskr/schema.sql'.

    This function reads the SQL schema file (expected to be located within the application
    package) and executes its contents to create the necessary tables and structure in the
    database. This function is typically used when first setting up the application or when
    resetting the database.
    """
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


@click.command('init-db')
def init_db_command() -> None:
    """
    Command-line command for initializing the SQLite database.

    Executes the `init_db()` function to clear existing data and create new tables, then
    outputs a message confirming successful initialization.

    Usage: flask init-db
    """
    init_db()
    click.echo('Initialized the database.')


def init_app(app: Flask) -> None:
    """
    Registers the database functions with the provided Flask application instance.

    Adds the `close_db()` function to the app's teardown context to ensure the database
    connection is closed at the end of each request. Also registers the `init-db` CLI command
    for initializing the database.

    Args:
        app (Flask): The Flask application instance to which the database functions should be registered.
    """
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
