# ASGI entry point for PythonAnywhere's experimental ASGI support
# Use this instead of wsgi.py if PythonAnywhere supports ASGI

import sys
import os

# Add the app directory to the path if needed
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app import create_app

# Create the FastAPI app instance
# PythonAnywhere's ASGI support expects the app variable
app = create_app()
