# FastAPI application entry point
# NOTE: For PythonAnywhere, use wsgi.py instead of this file
# This file is for local development with uvicorn

import sys
import os

# Add the app directory to the path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

app = create_app()

# For PythonAnywhere, you MUST use wsgi.py, not this file
# This file exports an ASGI app which won't work with PythonAnywhere's WSGI server
