import datetime
import re
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for
from jinjaMarkdown.markdownExtension import markdownExtension
import json
import os
import requests
import sys
import time
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask_caching import Cache


def get_cache_path(cachedir, source, cve):
    """
    Get cache path
    """
    return f'{cachedir}/{source}/{cve}.json'


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

    cachefile = get_cache_path(cachedir, source, cve)
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

    cachefile = get_cache_path(cachedir, source, cve)

    with open(cachefile, 'w') as f:
        json.dump(data, f)

    return


def validate_cve_id(cve_id):
    """
    Validate that a string matches CVE ID format (CVE-YYYY-NNNN+)
    :param cve_id: string to validate
    :return: bool indicating if string matches CVE ID format
    """
    cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
    return bool(cve_pattern.match(cve_id))


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
        try:
            response = requests.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_name}',
                timeout=10  # Add timeout
            )
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
        except requests.exceptions.Timeout:
            return NVD(None)

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
        try:
            response = requests.get(
                f'https://cveawg.mitre.org/api/cve/{cve_name}',
                timeout=10
            )
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
        except requests.exceptions.Timeout:
            return CVE(None)

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
        try:
            # Red Hat uses year-based subdirectories
            year     = cve_name[4:8]
            response = requests.get(
                f'https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_name.lower()}.json',
                timeout=10
            )
            if response.status_code != 200:
                return None

            vex_cve = response.json()
            vex     = Vex(vex_cve)
            cache(cachedir, 'vex', cve_name, vex_cve)
        except requests.exceptions.Timeout:
            return None

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
        try:
            response = requests.get(
                f'https://api.first.org/data/v1/epss?cve={cve_name}',
                timeout=10
            )
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
        except requests.exceptions.Timeout:
            return None

    return epss


def fix_delta(release, pkgs):
    """
    Calculate the number of days between vulnerability public date and fix release dates
    :param release: string containing the vulnerability public date (YYYY-MM-DD)
    :param pkgs: VexPackages object containing fix information
    :return: dict mapping package IDs to number of days between public and fix dates
    """
    # figure out the days from public to release
    deltas = {}
    rd     = datetime.datetime.strptime(release, "%Y-%m-%d")            # public date format

    for x in pkgs.fixes:
        xd           = datetime.datetime.strptime(x.date, "%B %d, %Y")  # release date format
        delta        = xd - rd
        deltas[x.id] = delta.days

    return deltas


csrf = CSRFProtect()

def create_session():
    """
    Create a requests Session with retry logic and connection pooling
    :return: configured requests.Session object with:
        - 3 retries with exponential backoff
        - Connection pooling (10 connections)
        - Automatic retries on 500-level errors
    """
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def get_all_data(cachedir, Vex, NVD, CVE, cve_name):
    """
    Get all external data concurrently from NVD, CVE.org, and EPSS
    :param cachedir: directory of the cache
    :param Vex: Vex object class
    :param NVD: NVD object class
    :param CVE: CVE object class
    :param cve_name: cve to look up
    :return: tuple of (nvd, cve, epss) objects
        nvd: NVD object containing NVD vulnerability data
        cve: CVE object containing CVE.org data
        epss: dict containing EPSS scoring data
    """
    with ThreadPoolExecutor(max_workers=3) as executor:
        nvd_future = executor.submit(get_from_nvd, cachedir, NVD, cve_name)
        cve_future = executor.submit(get_from_cve, cachedir, CVE, cve_name)
        epss_future = executor.submit(get_from_epss, cachedir, cve_name)
        
        nvd = nvd_future.result()
        cve = cve_future.result()
        epss = epss_future.result()
        
    return nvd, cve, epss


def determine_cvss_version(vex, nvd, cve):
    """
    Determine which CVSS version to use based on available data
    :param vex: Vex object containing vulnerability data
    :param nvd: NVD object containing NVD vulnerability data
    :param cve: CVE object containing CVE.org data
    :return: string indicating CVSS version ('3.1', '3.0', or '2.0')
    """
    if vex.global_cvss.version:
        return vex.global_cvss.version
        
    if nvd.cvss31.version or cve.cvss31.version:
        return '3.1'
        
    if nvd.cvss30.version or cve.cvss30.version:
        return '3.0'
        
    return '2.0'


def create_app():
    """
    Create and configure the Flask application
    :return: configured Flask application with:
        - CSRF protection
        - Proxy fix for security headers
        - Template extensions
        - Cache configuration
        - Error handlers
        - Route handlers
    """
    app = Flask(__name__, instance_relative_config=True)
    app.session = create_session()  # Create a shared session
    cache = Cache(app, config={
        'CACHE_TYPE': 'simple',
        'CACHE_DEFAULT_TIMEOUT': 300
    })

    # Load config first
    app.config.from_pyfile('config.py')

    # Ensure we have a secret key
    if not app.config.get('SECRET_KEY'):
        raise RuntimeError(
            'No SECRET_KEY set. Please add SECRET_KEY to instance/config.py'
        )

    csrf.init_app(app)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.jinja_env.add_extension(markdownExtension)

    cachedir = app.config['CACHE_DIRECTORY']
    beacon   = None if app.config['TESTING'] else app.config['CLOUDFLARE_BEACON']
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
        form = FlaskForm()  # Create an empty form for CSRF
        return render_template('search.html', form=form)

    @app.route('/cve', methods=['POST'])
    def redirect_cve():
        cve = request.form['cve']
        return redirect(url_for('render_cve', cve=cve))

    @app.route('/cve/<cve>')
    @cache.memoize(timeout=300)  # Cache for 5 minutes
    def render_cve(cve=None):
        if not cve:
            return render_template('cve_not_found.html'), 404

        if not validate_cve_id(cve):
            return render_template('cve_not_valid.html', cve=cve), 404

        vex = get_from_redhat(cachedir, Vex, cve)
        if not vex:
            return render_template('cve_not_found.html', cve=cve), 404
        
        packages = VexPackages(vex.raw)
        nvd, cve, epss = get_all_data(cachedir, Vex, NVD, CVE, vex.cve)

        cvssVersion = determine_cvss_version(vex, nvd, cve)
        
        # Apply CVSS version
        if cvssVersion == '3.1':
            nvd = nvd.cvss31 if nvd.cvss31.version else nvd.cvss30
            cve = cve.cvss31 if cve.cvss31.version else cve.cvss30
        elif cvssVersion == '3.0':
            nvd = nvd.cvss30
            cve = cve.cvss30
        else:  # 2.0
            nvd = nvd.cvss20
            cve = cve.cvss20

        fixdeltas = fix_delta(vex.release_date, packages)

        return render_template('cve.html', vex=vex,
                               packages=packages, nvd=nvd, cve=cve, epss=epss,
                               cvssVersion=cvssVersion, fixdeltas=fixdeltas, beacon=beacon)

    return app
