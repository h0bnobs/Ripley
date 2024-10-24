"""
This script runs the gui version of the tool
"""
import webbrowser
import threading
from flaskr import create_app
import time
import os

PORT = 5000


def run_flask_app():
    app = create_app()
    app.run(port=PORT)


if __name__ == '__main__':
    # starts the Flask app in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    # this script should be run from proj root!
    os.makedirs('flaskr/static/screenshots', exist_ok=True)
    os.makedirs('flaskr/static/js', exist_ok=True)
    time.sleep(1)
    webbrowser.open(f'http://localhost:{PORT}')

    # waits for the Flask thread to finish (or indefinitely)
    flask_thread.join()
