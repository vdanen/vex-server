#!/bin/sh

source .venv/bin/activate
.venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 --access-logfile - --timeout 90 -k gevent 'app:create_app()'
deactivate
