# vex-server
This is mostly a proof of concept to illustrate that VEX documents aren't
just the new shiny thing, but they're actually pretty darn functional.

It's a quick-and-dirty recreation of the Red Hat CVE pages using the NVD
API and the Red Hat VEX files that are located at
https://access.redhat.com/security/data/csaf/v2/vex/2024/

It uses my [vex-reader](https://pypi.org/project/vex-reader/) Python module
and shows CVE pages for Red Hat VEX documents using the Flask framework.

Copy the `instance/config.py.example` to `instance/config.py` to set the
location of the cache directory.  Should be all the configuration this
needs.

Use GitHub issues to file any bugs.  You can also [report security
vulnerabilities](https://github.com/vdanen/vex-server/security/advisories/new)
in GitHub.  Contributions are welcome if you're so inclined.

## Configuration

Copy `instance/config.py.example` to `instance/config.py`.  The
configuration file is very self-explanatory.

## Running

It is recommended to use python 3.9.  Later versions are not currently
supported.

To run the demo server, ensure the configured cache directory in
`config.py` exists: `mkdir -p cache/{cve,vex,nvd,epss,kev}`

Create a virtual environment: `python -m venv .venv`.  Install the required
dependencies with `pip install -r requirements.txt`.

Start the demo server by running `sh gunicorn-start.sh`.  This will start
the gunicorn server listening on the localhost.

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10739/badge)](https://www.bestpractices.dev/projects/10739)
