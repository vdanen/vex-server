import datetime
import re
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request, redirect, url_for
import json
import os
import pytz
import requests
import sys
import time
import vulncheck_sdk
import markdown
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask_caching import Cache


def get_cache_path(cachedir, source, cve):
    """
    Get the file path for a cached document
    :param cachedir: directory of the cache
    :param source: one of vex, cve, nvd, epss, kev
    :param cve: cve to look up
    :return: string containing the full path to the cache file
    """
    # Sanitize CVE to prevent path traversal attacks
    # Remove any path separators and normalize
    safe_cve = os.path.basename(cve).replace('/', '').replace('\\', '')
    # Construct path safely using os.path.join
    cache_path = os.path.join(cachedir, source, f'{safe_cve}.json')
    # Normalize and resolve to absolute path to prevent traversal
    cache_path = os.path.normpath(cache_path)
    # Ensure the path is within the cache directory
    cachedir_abs = os.path.abspath(cachedir)
    cache_path_abs = os.path.abspath(cache_path)
    if not cache_path_abs.startswith(cachedir_abs):
        raise ValueError(f'Invalid cache path: {cache_path}')
    return cache_path


def get_cached(cachedir, source, cve):
    """
    Check for and return a cached copy of a document
    :param cachedir: directory of the cache
    :param source: one of vex, cve, nvd, epss
    :param cve: cve to look up
    :return: json
    """
    if source not in ['vex', 'cve', 'nvd', 'epss', 'kev']:
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
    if source not in ['vex', 'cve', 'nvd', 'epss', 'kev']:
        print(f'ERROR: Invalid source: {source}')
        sys.exit(1)

    cachefile = get_cache_path(cachedir, source, cve)

    # Ensure the cache directory exists
    # cachefile is already validated to be within cachedir, so dirname is safe
    cache_dir = os.path.dirname(cachefile)
    os.makedirs(cache_dir, exist_ok=True)

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


def get_from_kev(cachedir, cve_name, vulncheck):
    """
    Get details from VulnCheck KEV for this CVE and return it as a kev dict
    :param cachedir: directory of the cache
    :param cve_name: cve to look up
    :return: dict
    """
    cached = get_cached(cachedir, 'kev', cve_name)
    if cached:
        kev = cached
    else:
        vconfig = vulncheck_sdk.Configuration(host='https://api.vulncheck.com/v3')
        vconfig.api_key["Bearer"] = vulncheck

        kev = None
        with vulncheck_sdk.ApiClient(vconfig) as api_client:
            indices_client = vulncheck_sdk.IndicesApi(api_client)

            try:
                api_response = indices_client.index_vulncheck_kev_get(cve=cve_name)

                for d in api_response.data:
                    # Python 3.11+ fromisoformat handles 'Z' suffix directly
                    # Normalize 'Z' to '+00:00' for consistent parsing
                    date_str = d.date_added.replace('Z', '+00:00') if d.date_added.endswith('Z') else d.date_added
                    xd = datetime.datetime.fromisoformat(date_str)
                    date_added = xd.astimezone(pytz.timezone('US/Eastern')).strftime('%B %d, %Y')
                    kev = {'cve'            : d.cve[0],
                           'cwes'           : d.cwes,
                           'cisa_date_added': d.cisa_date_added,
                           'ransomware'     : d.known_ransomware_campaign_use,
                           'date_added'     : date_added}
                    cache(cachedir, 'kev', cve_name, kev)
            except vulncheck_sdk.exceptions.BadRequestException:
                kev = None

    return kev


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


def get_all_data(cachedir, Vex, NVD, CVE, cve_name, vulncheck):
    """
    Get all external data concurrently from NVD, CVE.org, EPSS and VulnCheck KEV
    :param cachedir: directory of the cache
    :param Vex: Vex object class
    :param NVD: NVD object class
    :param CVE: CVE object class
    :param cve_name: cve to look up
    :param vulncheck: VulnCheck API token (None if not configured)
    :return: tuple of (nvd, cve, epss, kev) objects
        nvd: NVD object containing NVD vulnerability data
        cve: CVE object containing CVE.org data
        epss: dict containing EPSS scoring data
        kev: KEV object containing VulnCheck KEV data
    """
    # Determine number of workers based on whether VulnCheck is enabled
    max_workers = 4 if vulncheck else 3

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all downloads in parallel
        nvd_future = executor.submit(get_from_nvd, cachedir, NVD, cve_name)
        cve_future = executor.submit(get_from_cve, cachedir, CVE, cve_name)
        epss_future = executor.submit(get_from_epss, cachedir, cve_name)

        # Submit VulnCheck KEV in parallel if configured
        if vulncheck:
            kev_future = executor.submit(get_from_kev, cachedir, cve_name, vulncheck)
        else:
            kev_future = None

        # Wait for all results
        nvd = nvd_future.result()
        cve = cve_future.result()
        epss = epss_future.result()
        kev = kev_future.result() if kev_future else None
        
    return nvd, cve, epss, kev


def has_cvss_data(vex, nvd, cve):
    """
    Check if any CVSS data is available from any source
    :param vex: Vex object containing vulnerability data
    :param nvd: NVD object containing NVD vulnerability data
    :param cve: CVE object containing CVE.org data
    :return: bool indicating if CVSS data exists
    """
    # Check Red Hat VEX CVSS data
    if vex.global_cvss and hasattr(vex.global_cvss, 'baseScore') and vex.global_cvss.baseScore:
        return True

    # Check NVD and CVE CVSS data (check version attribute which indicates CVSS data exists)
    if hasattr(nvd, 'cvss31') and hasattr(nvd.cvss31, 'version') and nvd.cvss31.version:
        return True
    if hasattr(cve, 'cvss31') and hasattr(cve.cvss31, 'version') and cve.cvss31.version:
        return True
    if hasattr(nvd, 'cvss30') and hasattr(nvd.cvss30, 'version') and nvd.cvss30.version:
        return True
    if hasattr(cve, 'cvss30') and hasattr(cve.cvss30, 'version') and cve.cvss30.version:
        return True
    if hasattr(nvd, 'cvss20') and hasattr(nvd.cvss20, 'version') and nvd.cvss20.version:
        return True
    if hasattr(cve, 'cvss20') and hasattr(cve.cvss20, 'version') and cve.cvss20.version:
        return True

    return False


def determine_cvss_version(vex, nvd, cve):
    """
    Determine which CVSS version to use based on available data
    :param vex: Vex object containing vulnerability data
    :param nvd: NVD object containing NVD vulnerability data
    :param cve: CVE object containing CVE.org data
    :return: string indicating CVSS version ('3.1', '3.0', or '2.0')
    """
    if vex.global_cvss and hasattr(vex.global_cvss, 'version') and vex.global_cvss.version:
        return vex.global_cvss.version
        
    if nvd.cvss31.version or cve.cvss31.version:
        return '3.1'
        
    if nvd.cvss30.version or cve.cvss30.version:
        return '3.0'
        
    if nvd.cvss20.version or cve.cvss20.version:
        return '2.0'

    # Default to 3.1 if no CVSS data is found
    return '3.1'


def normalize_markdown_code_blocks(text):
    """
    Normalize markdown code blocks by converting ~~~ to ```.
    Some VEX files use ~~~ instead of the standard ``` for code blocks.
    """
    # Replace ~~~ with ``` at the start of lines
    # This handles both opening (~~~python) and closing (~~~) code blocks
    # The pattern matches ~~~ at the start of a line, optionally followed by language identifier
    # \w* matches word characters (language identifier like 'python', 'bash', etc.)
    text = re.sub(r'^~~~(\w*)', r'```\1', text, flags=re.MULTILINE)
    return text


def convert_bare_urls_to_markdown(text):
    """
    Convert bare URLs in text to markdown format for clickable links.
    Finds URLs and converts them to [url](url) format.
    """
    # Regex pattern to match URLs (http, https, ftp)
    url_pattern = r'(?<![\[\(])(https?://[^\s\)\]]+|ftp://[^\s\)\]]+)(?![\]\)])'

    def replace_url(match):
        url = match.group(1)
        return f'[{url}]({url})'

    # Replace bare URLs with markdown format
    return re.sub(url_pattern, replace_url, text)


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

    # Update cache configuration to use full path
    cache = Cache(app, config={
        'CACHE_TYPE': 'flask_caching.backends.SimpleCache',
        'CACHE_DEFAULT_TIMEOUT': 300
    })

    # Load config first
    app.config.from_pyfile('config.py')

    # Ensure we have a secret key
    if not app.config.get('SECRET_KEY'):
        raise RuntimeError(
            'No SECRET_KEY set. Please add SECRET_KEY to instance/config.py'
        )

    # enable vulncheck KEV if we have a token
    vulncheck = app.config.get('VULNCHECK_API_TOKEN')

    csrf.init_app(app)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    cachedir = app.config['CACHE_DIRECTORY']
    beacon   = None if 'CLOUDFLARE_BEACON' not in app.config  else app.config['CLOUDFLARE_BEACON']
    if app.config['TESTING']:
        # for local development on pre-release vex-reader
        import sys
        sys.path.append(app.config['OVERRIDE_VEX_READER'])
        beacon = None

    # we can only import vex after we know whether we're in testing mode or not
    from vex import Vex, VexPackages, NVD, CVE

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Ensure cache directories exist
    for subdir in ['cve', 'vex', 'nvd', 'epss', 'kev']:
        cache_subdir = os.path.join(cachedir, subdir)
        try:
            os.makedirs(cache_subdir, exist_ok=True)
        except OSError:
            pass

    @app.template_filter('safe_getattr')
    def safe_getattr_filter(obj, attr, default='N/A'):
        """
        Safely get an attribute from an object, returning default if attribute doesn't exist
        :param obj: object to get attribute from
        :param attr: attribute name to get
        :param default: default value to return if attribute doesn't exist
        :return: attribute value or default
        """
        if obj is None:
            return default
        return getattr(obj, attr, default)

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('page_not_found.html'), 404

    @app.route('/')
    def home():
        form = FlaskForm()  # Create an empty form for CSRF
        return render_template('search.html', form=form)

    @app.route('/cve', methods=['GET', 'POST'])
    def redirect_cve():
        if request.method == 'POST':
            cve = request.form['cve']
            return redirect(url_for('render_cve', cve=cve))
        else:
            # GET request to /cve without a CVE name
            return render_template('cve_not_found.html'), 404

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
        nvd, cve, epss, kev = get_all_data(cachedir, Vex, NVD, CVE, vex.cve, vulncheck)

        # Check if CVSS data exists before determining version
        has_cvss = has_cvss_data(vex, nvd, cve)
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

        # let's make sure that the not affects aren't a list of containers because
        # no one really cares which containers aren't affected and it's just a
        # silly long list anyways
        not_affected = []
        for x in packages.not_affected:
            include = True
            for a in x.components:
                if '@sha256' in a:
                    include=False
            if include:
                not_affected.append(x)

        # do the markdown transformations here, not as jinja filters
        mitigation = ''
        # we just want the first one
        if len(packages.mitigation) > 0:
            # Normalize code blocks, convert bare URLs to markdown format, then process markdown
            m_text     = normalize_markdown_code_blocks(packages.mitigation[0].details)
            m_text     = convert_bare_urls_to_markdown(m_text)
            mitigation = markdown.markdown(m_text)

        statement = ''
        if 'other' in vex.notes:
            if 'Statement' in vex.notes['other']:
                s_text = normalize_markdown_code_blocks(vex.notes['other']['Statement'])
                s_text = convert_bare_urls_to_markdown(s_text)
                statement = markdown.markdown(s_text)
            else:
                statement = ''

        if 'description' in vex.notes:
            if 'Vulnerability description' in vex.notes['description']:
                d_text = normalize_markdown_code_blocks(vex.notes['description']['Vulnerability description'])
                d_text = convert_bare_urls_to_markdown(d_text)
                description = markdown.markdown(d_text)
            else:
                description = ''
        else:
            description = ''

        return render_template('cve.html', vex=vex, nvd=nvd, cve=cve, epss=epss,
                               cvssVersion=cvssVersion, has_cvss=has_cvss, fixdeltas=fixdeltas, beacon=beacon, kev=kev,
                               fixes=packages.fixes, not_affected=not_affected,
                               wontfix=packages.wontfix, affected=packages.affected,
                               mitigation=mitigation, statement=statement, description=description)

    return app
