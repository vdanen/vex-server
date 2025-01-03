from flask import Flask, render_template, request, redirect, url_for
from jinjaMarkdown.markdownExtension import markdownExtension
import json
import os
import requests
import sys
import time


def get_cached(cachedir, source, cve):
    """
    Check for and return a cached copy of a document
    :param cachedir: directory of the cache
    :param source: one of vex, cve, nvd, epss
    :param cve: cve to look up
    :return: json
    """
    if source not in ['vex', 'cve', 'nvd', 'epss']:
        print(f'ERROR: Invalid source: {source}')
        sys.exit(1)

    cachefile = f'{cachedir}/{source}/{cve}.json'
    if not os.path.exists(cachefile):
        return None

    hour_ago = time.time() - 60 * 60
    if hour_ago > os.path.getctime(cachefile):
        # this file is at least an hour old, get a new one
        os.remove(cachefile)
        return None

    with open(cachefile, 'r') as f:
        j = json.load(f)

    return j


def cache(cachedir, source, cve, data):
    """
    Cache retrieved data
    :param cachedir: directory of the cache
    :param source: one of vex, cve, nvd, epss
    :param cve: cve to look up
    :param data: json data
    :return:
    """
    if source not in ['vex', 'cve', 'nvd', 'epss']:
        print(f'ERROR: Invalid source: {source}')
        sys.exit(1)

    cachefile = f'{cachedir}/{source}/{cve}.json'

    with open(cachefile, 'w') as f:
        json.dump(data, f)

    return


def get_from_nvd(cachedir, NVD, cve_name):
    """
    Get details from NVD for this CVE and return it as a simple NVD object
    :param cachedir: directory of the cache
    :param NVD: NVD object
    :param cve_name: cve to look up
    :return: NVD object
    """
    cached = get_cached(cachedir,'nvd', cve_name)
    if cached:
        nvd = NVD(cached)
    else:
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_name}')
        if response.status_code != 200:
            return NVD(None)

        nvd_cve  = response.json()
        if len(nvd_cve['vulnerabilities']) > 0:
            # we have a result
            if nvd_cve['vulnerabilities'][0]['cve']['id'] == cve_name:
                # we got the right result, cache and use it
                nvd = NVD(nvd_cve)
                cache(cachedir,'nvd', cve_name, nvd_cve)
            else:
                nvd = NVD(None)
        else:
            nvd = NVD(None)

    return nvd


def get_from_cve(cachedir, CVE, cve_name):
    """
    Get details from CVE.org for this CVE and return it as a simple CVE object
    :param cachedir: directory of the cache
    :param CVE: CVE object
    :param cve_name: cve to look up
    :return: CVE object
    """
    cached = get_cached(cachedir, 'cve', cve_name)
    if cached:
        cve = CVE(cached)
    else:
        response = requests.get(f'https://cveawg.mitre.org/api/cve/{cve_name}')
        if response.status_code != 200:
            return CVE(None)

        cve_cve  = response.json()
        if 'cveMetadata' in cve_cve:
            # we have a result
            if cve_cve['cveMetadata']['cveId'] == cve_name:
                # we got the right result, cache and use it
                cve = CVE(cve_cve)
                cache(cachedir, 'cve', cve_name, cve_cve)
            else:
                cve = CVE(None)
        else:
            cve = CVE(None)

    return cve


def get_from_redhat(cachedir, Vex, cve_name):
    """
    Get details from Red Hat for this CVE and return it as a Vex object
    :param cachedir: directory of the cache
    :param Vex: Vex object
    :param cve_name: cve to look up
    :return: Vex object
    """
    cached = get_cached(cachedir,'vex', cve_name)
    if cached:
        vex = Vex(cached)
    else:
        # Red Hat uses year-based subdirectories
        year     = cve_name[4:8]
        response = requests.get(f'https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_name.lower()}.json')
        if response.status_code != 200:
            return None

        vex_cve = response.json()
        vex     = Vex(vex_cve)
        cache(cachedir, 'vex', cve_name, vex_cve)

    return vex


def get_from_epss(cachedir, cve_name):
    """
    Get details from FIRST EPSS for this CVE and return it as an epss dict
    :param cachedir: directory of the cache
    :param cve_name: cve to look up
    :return: dict
    """
    cached = get_cached(cachedir, 'epss', cve_name)
    if cached:
        epss = cached
    else:
        response = requests.get(f'https://api.first.org/data/v1/epss?cve={cve_name}')
        if response.status_code != 200:
            return None

        epss_cve = response.json()
        if len(epss_cve['data']) > 0:
            # we have a result
            if epss_cve['data'][0]['cve'] == cve_name:
                # we got the right result
                epss = {'cve'    : cve_name,
                        'date'   : epss_cve['data'][0]['date'],
                        'percent': '%.2f' % (float(epss_cve['data'][0]['percentile']) * 100),
                        'score'  : str(epss_cve['data'][0]['epss']).rstrip('0')
                        }
                cache(cachedir, 'epss', cve_name, epss)
            else:
                epss = None
        else:
            epss = None

    return epss


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.jinja_env.add_extension(markdownExtension)
    app.config.from_pyfile('config.py')

    cachedir = app.config['CACHE_DIRECTORY']
    if app.config['TESTING']:
        # for local development on pre-release vex-reader
        import sys
        sys.path.append(app.config['OVERRIDE_VEX_READER'])

    # we can only import vex after we know whether we're in testing mode or not
    from vex import Vex, VexPackages, NVD, CVE

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

        vex      = get_from_redhat(cachedir, Vex, cve)
        if not vex:
            return render_template('cve_not_found.html'), 404
        packages = VexPackages(vex.raw)
        nvd      = get_from_nvd(cachedir, NVD, vex.cve)
        cve      = get_from_cve(cachedir, CVE, vex.cve)
        epss     = get_from_epss(cachedir, vex.cve)

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

        return render_template('cve.html', vex=vex, packages=packages, nvd=nvd, cve=cve, epss=epss, cvssVersion=cvssVersion)

    return app
