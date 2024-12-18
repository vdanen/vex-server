localdev = False

from flask import Flask, render_template, request, redirect, url_for
from jinjaMarkdown.markdownExtension import markdownExtension
import os
import requests
if localdev:
    # for local development on pre-release vex-reader
    import sys
    sys.path.append('/Users/redhat/git/vex-reader')
from vex import Vex, VexPackages, NVD, CVE

# whether or not to load VEX files locally or remotely
localvex = False

def get_from_nvd(cve):
    response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}')
    if response.status_code != 200:
        return NVD(None)

    nvd_cve  = response.json()
    if len(nvd_cve['vulnerabilities']) > 0:
        # we have a result
        if nvd_cve['vulnerabilities'][0]['cve']['id'] == cve:
            # we got the right result
            nvd = NVD(nvd_cve)
        else:
            nvd = NVD(None)
    else:
        nvd = NVD(None)

    return nvd


def get_from_cve(cve):
    response = requests.get(f'https://cveawg.mitre.org/api/cve/{cve}')
    if response.status_code != 200:
        return CVE(None)

    cve_cve  = response.json()
    if 'cveMetadata' in cve_cve:
        # we have a result
        if cve_cve['cveMetadata']['cveId'] == cve:
            # we got the right result
            cve = CVE(cve_cve)
        else:
            cve = CVE(None)
    else:
        cve = CVE(None)

    return cve


def get_from_epss(cve):
    response = requests.get(f'https://api.first.org/data/v1/epss?cve={cve}')
    if response.status_code != 200:
        return None

    epss_cve = response.json()
    if len(epss_cve['data']) > 0:
        # we have a result
        if epss_cve['data'][0]['cve'] == cve:
            # we got the right result
            epss = {'cve'    : cve,
                    'date'   : epss_cve['data'][0]['date'],
                    'percent': '%.2f' % (float(epss_cve['data'][0]['percentile']) * 100),
                    'score'  : str(epss_cve['data'][0]['epss']).rstrip('0')
                    }
        else:
            epss = None
    else:
        epss = None

    return epss


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
            # grab from remote and handle any errors here rather than in vex-reader
            vexfile = f'https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve.lower()}.json'
            response = requests.get(vexfile)
            if response.status_code == 200:
                with open(f'{cve}.json', 'w') as f:
                    f.write(response.text)
            elif response.status_code == 404:
                return render_template('cve_not_found.html'), 404
            else:
                return render_template('page_not_found.html'), 404
            vexfile = f'{cve}.json'

        vex      = Vex(vexfile)
        packages = VexPackages(vex.raw)
        nvd      = get_from_nvd(vex.cve)
        cve      = get_from_cve(vex.cve)
        epss     = get_from_epss(vex.cve)

        # what CVSS metrics do we display?  Does our VEX provide any?
        cvssVersion = 0

        if vex.global_cvss.version is not None:
            # this is our default
            cvssVersion = vex.global_cvss.version

        if cvssVersion == 0:
            if nvd.cvss31.version is not None:
                cvssVersion = '3.1'
            elif cve.cvss31.version is not None:
                cvssVersion = '3.1'

        if cvssVersion == '3.1':
            # we can display either 3.1 or 3.0
            if nvd.cvss31.version is not None:
                nvd = nvd.cvss31
            else:
                nvd = nvd.cvss30
            if cve.cvss31.version is not None:
                cve = cve.cvss31
            else:
                cve = cve.cvss30

        if cvssVersion == '3.0':
            cve = cve.cvss30
            nvd = nvd.cvss30

        if cvssVersion == '2.0':
            cve = cve.cvss20
            nvd = nvd.cvss20

        if not localvex:
            os.remove(vexfile)

        return render_template('cve.html', vex=vex, packages=packages, nvd=nvd, cve=cve, year=year, epss=epss, cvssVersion=cvssVersion)

    return app
