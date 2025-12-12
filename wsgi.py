# WSGI entry point for PythonAnywhere
# This wraps the FastAPI ASGI app in a WSGI adapter

import sys
import os

# Add the app directory to the path if needed
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import and create the FastAPI app
from app import create_app

# Create the FastAPI app instance
fastapi_app = create_app()

# Wrap it using a2wsgi to make it WSGI-compatible
# Try a2wsgi first, fallback to mangum if needed
try:
    from a2wsgi import ASGIMiddleware
    # The ASGIMiddleware wraps the ASGI app and makes it WSGI-compatible
    # PythonAnywhere expects a variable named 'application'
    application = ASGIMiddleware(fastapi_app)
except (ImportError, Exception) as e:
    # Fallback to mangum if a2wsgi doesn't work
    try:
        from mangum import Mangum
        # Mangum also converts ASGI to WSGI
        application = Mangum(fastapi_app)
    except ImportError:
        # If neither works, provide a helpful error
        raise ImportError(
            "Either a2wsgi or mangum is required for WSGI compatibility. "
            "Please install one with: pip install a2wsgi (or pip install mangum)"
        ) from e
