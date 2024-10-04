from flask import Flask, render_template, request, redirect, url_for
from jinjaMarkdown.markdownExtension import markdownExtension
import os
import requests
from vex import Vex, VexPackages, NVD

# whether or not to load VEX files locally or remotely
localvex = False

def get_from_nvd(cve):
    response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}')
    nvd_cve  = response.json()
    if nvd_cve['vulnerabilities'][0]['cve']['id'] == cve:
        # we got the right result
        if 'cvssMetricV31' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
            nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData'])
        elif 'cvssMetricV30' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
            nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData'])
        elif 'cvssMetricV2' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
            nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'])
        else:
            nvd = NVD(None)

    return nvd


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.jinja_env.add_extension(markdownExtension)
    #app.config.from_pyfile('config.py')

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('page_not_found.html'), 404

    @app.route('/')
    def home():
        return render_template('search.html')

    @app.route('/cve', methods=['POST'])
    def redirect_cve():
        cve = request.form['cve']
        return redirect(url_for('render_cve', cve=cve))

    @app.route('/cve/<cve>')
    def render_cve(cve=None):
        if not cve:
            return render_template('page_not_found.html'), 404

        # VEX files are in year-based directories, so pull the CVE year
        vexdir  = '/Users/redhat/git/redhat-vex/'
        year    = cve[4:8]

        if localvex:
            vexfile = f'{vexdir}/{year}/{cve}.json'
            if not os.path.exists(vexfile):
                return render_template('cve_not_found.html'), 404
        else:
            vexfile = f'https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve.lower()}.json'

        vex      = Vex(vexfile)
        packages = VexPackages(vex.raw)
        nvd      = get_from_nvd(vex.cve)

        return render_template('cve.html', vex=vex, packages=packages, nvd=nvd, year=year)

    return app
