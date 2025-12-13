# FastAPI application entry point
# This file is for local development with uvicorn
# For production (Heroku, etc.), use asgi.py or configure to use this file

import sys
import os

# Add the app directory to the path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

app = create_app()
