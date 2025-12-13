# ASGI entry point for Heroku and other ASGI-compatible platforms

import sys
import os

# Add the app directory to the path if needed
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app import create_app

# Create the FastAPI app instance
app = create_app()
