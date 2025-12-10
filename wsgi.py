# WSGI entry point for PythonAnywhere
# This wraps the FastAPI ASGI app in a WSGI adapter

import sys
import os

# Add the app directory to the path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from a2wsgi import ASGIMiddleware
from app import create_app

# Create the FastAPI app
app = create_app()

# Wrap it in ASGIMiddleware to make it WSGI-compatible
application = ASGIMiddleware(app)
