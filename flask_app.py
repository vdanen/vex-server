# to run via PythonAnywhere

import sys
sys.path = ['/home/vdanen/cve/app'] + sys.path

import app

app = app.create_app()

