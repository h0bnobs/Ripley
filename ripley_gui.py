"""
This script runs the gui version of the tool
"""
import webbrowser
import threading
from flaskr import create_app
import time
import os
from scripts.run_commands import run_command_no_output

PORT = 5000

def run_flask_app():
    """
    Runs flask on port 5000.
    """
    app = create_app()
    app.run(port=PORT)


if __name__ == '__main__':
    """
    Starts the Flask app in a separate thread, sets up necessary directories,
    and opens the web browser to the Flask app URL.
    """
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    # this script should be run from proj root!
    run_command_no_output('rm -rf flaskr/static/temp')
    os.makedirs('flaskr/static/screenshots', exist_ok=True)
    os.makedirs('flaskr/static/js', exist_ok=True)
    time.sleep(1)
    webbrowser.open(f'http://localhost:{PORT}')

    # waits for the Flask thread to finish (or indefinitely)
    flask_thread.join()
