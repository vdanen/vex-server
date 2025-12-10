#!/bin/sh

source .venv/bin/activate
.venv/bin/uvicorn fastapi_app:app --host 127.0.0.1 --port 5000 --workers 4
deactivate
