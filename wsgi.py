# WSGI entry point for PythonAnywhere
# This wraps the FastAPI ASGI app in a WSGI adapter

import sys
import os

# Add the app directory to the path if needed
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Set environment variable to use sync requests for WSGI compatibility
os.environ['USE_SYNC_REQUESTS'] = 'true'

# Import and create the FastAPI app
# Note: This happens at import time, so keep it fast
try:
    from app import create_app
    
    # Create the FastAPI app instance
    fastapi_app = create_app()
    
    # Wrap it using a2wsgi to make it WSGI-compatible
    # Note: WSGI adapters have limitations with async operations
    # For better performance, consider using PythonAnywhere's ASGI support
    try:
        from a2wsgi import ASGIMiddleware
        # The ASGIMiddleware wraps the ASGI app and makes it WSGI-compatible
        # Set wait_time to prevent hanging on background tasks (30 seconds max)
        # PythonAnywhere expects a variable named 'application'
        application = ASGIMiddleware(
            fastapi_app,
            wait_time=30.0,  # Max wait time for background tasks
            loop=None  # Use default event loop
        )
    except (ImportError, Exception) as e:
        # Fallback to mangum if a2wsgi doesn't work
        try:
            from mangum import Mangum
            # Mangum also converts ASGI to WSGI
            # Set lifespan to 'off' to avoid issues with startup/shutdown
            application = Mangum(
                fastapi_app,
                lifespan="off",  # Disable lifespan events
                log_level="info"  # Enable logging for debugging
            )
        except ImportError:
            # If neither works, provide a helpful error
            raise ImportError(
                "Either a2wsgi or mangum is required for WSGI compatibility. "
                "Please install one with: pip install a2wsgi (or pip install mangum). "
                "Alternatively, use PythonAnywhere's experimental ASGI support with asgi.py"
            ) from e
except Exception as e:
    # Provide a helpful error message if app creation fails
    import traceback
    error_msg = f"Failed to create application: {str(e)}\n{traceback.format_exc()}"
    print(error_msg, file=sys.stderr)
    
    # Create a minimal WSGI app that shows the error
    def error_app(environ, start_response):
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/plain')]
        start_response(status, headers)
        return [error_msg.encode('utf-8')]
    
    application = error_app
