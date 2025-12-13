import datetime
import re
import json
import os
import pytz
import sys
import time
import asyncio
import vulncheck_sdk
import markdown
from functools import lru_cache
from fastapi import FastAPI, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import httpx


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


async def get_from_nvd(cachedir, NVD, cve_name, client: httpx.AsyncClient):
    """
    Get details from NVD for this CVE and return it as a simple NVD object
    :param cachedir: directory of the cache
    :param NVD: NVD object
    :param cve_name: cve to look up
    :param client: httpx async client
    :return: NVD object
    """
    cached = get_cached(cachedir,'nvd', cve_name)
    if cached:
        nvd = NVD(cached)
    else:
        try:
            response = await client.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_name}',
                timeout=10.0
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
        except (httpx.TimeoutException, httpx.RequestError):
            return NVD(None)

    return nvd


async def get_from_cve(cachedir, CVE, cve_name, client: httpx.AsyncClient):
    """
    Get details from CVE.org for this CVE and return it as a simple CVE object
    :param cachedir: directory of the cache
    :param CVE: CVE object
    :param cve_name: cve to look up
    :param client: httpx async client
    :return: CVE object
    """
    cached = get_cached(cachedir, 'cve', cve_name)
    if cached:
        cve = CVE(cached)
    else:
        try:
            response = await client.get(
                f'https://cveawg.mitre.org/api/cve/{cve_name}',
                timeout=10.0
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
        except (httpx.TimeoutException, httpx.RequestError):
            return CVE(None)

    return cve


async def get_from_redhat(cachedir, Vex, cve_name, client: httpx.AsyncClient):
    """
    Get details from Red Hat for this CVE and return it as a Vex object
    :param cachedir: directory of the cache
    :param Vex: Vex object
    :param cve_name: cve to look up
    :param client: httpx async client
    :return: Vex object
    """
    cached = get_cached(cachedir,'vex', cve_name)
    if cached:
        vex = Vex(cached)
    else:
        try:
            # Red Hat uses year-based subdirectories
            year     = cve_name[4:8]
            response = await client.get(
                f'https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_name.lower()}.json',
                timeout=10.0
            )
            if response.status_code != 200:
                return None

            vex_cve = response.json()
            vex     = Vex(vex_cve)
            cache(cachedir, 'vex', cve_name, vex_cve)
        except (httpx.TimeoutException, httpx.RequestError):
            return None

    return vex


async def get_from_epss(cachedir, cve_name, client: httpx.AsyncClient):
    """
    Get details from FIRST EPSS for this CVE and return it as an epss dict
    :param cachedir: directory of the cache
    :param cve_name: cve to look up
    :param client: httpx async client
    :return: dict
    """
    cached = get_cached(cachedir, 'epss', cve_name)
    if cached:
        epss = cached
    else:
        try:
            response = await client.get(
                f'https://api.first.org/data/v1/epss?cve={cve_name}',
                timeout=10.0
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
        except (httpx.TimeoutException, httpx.RequestError):
            return None

    return epss


def get_from_kev(cachedir, cve_name, vulncheck):
    """
    Get details from VulnCheck KEV for this CVE and return it as a kev dict
    Note: This function is synchronous because vulncheck_sdk is synchronous
    :param cachedir: directory of the cache
    :param cve_name: cve to look up
    :param vulncheck: VulnCheck API token
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


async def get_all_data(cachedir, Vex, NVD, CVE, cve_name, vulncheck):
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
    # Create a shared httpx client for async requests
    async with httpx.AsyncClient() as client:
        # Run all async requests concurrently
        tasks = [
            get_from_nvd(cachedir, NVD, cve_name, client),
            get_from_cve(cachedir, CVE, cve_name, client),
            get_from_epss(cachedir, cve_name, client),
        ]

        # Add VulnCheck KEV if configured (note: this is still sync, so run in executor)
        if vulncheck:
            loop = asyncio.get_event_loop()
            kev_task = loop.run_in_executor(None, get_from_kev, cachedir, cve_name, vulncheck)
            tasks.append(kev_task)
        else:
            # Create a coroutine that returns None
            async def get_none():
                return None
            tasks.append(get_none())

        results = await asyncio.gather(*tasks)
        nvd, cve, epss, kev = results
        
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


class ProxyFixMiddleware(BaseHTTPMiddleware):
    """Middleware to fix proxy headers (similar to Werkzeug ProxyFix)"""
    def __init__(self, app, x_for=1, x_proto=1):
        super().__init__(app)
        self.x_for = x_for
        self.x_proto = x_proto

    async def dispatch(self, request: Request, call_next):
        # Get the real IP from X-Forwarded-For header
        if self.x_for:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                # Take the first IP (client IP)
                client_ip = forwarded_for.split(",")[0].strip()
                request.scope["client"] = (client_ip, request.scope["client"][1])

        # Get the real protocol from X-Forwarded-Proto header
        if self.x_proto:
            forwarded_proto = request.headers.get("X-Forwarded-Proto")
            if forwarded_proto:
                request.scope["scheme"] = forwarded_proto

        response = await call_next(request)
        return response


def create_app():
    """
    Create and configure the FastAPI application
    :return: configured FastAPI application with:
        - Template rendering
        - Static file serving
        - Error handlers
        - Route handlers
    """
    # Determine instance path
    instance_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')

    app = FastAPI()

    # Load config from file first
    config_path = os.path.join(instance_path, 'config.py')
    config = {}
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            exec(compile(f.read(), config_path, 'exec'), config)

    # Override config with environment variables if they exist (Heroku support)
    # Priority: environment variable > config file
    # SECRET_KEY from environment or config file
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        secret_key = config.get('SECRET_KEY')
    if not secret_key:
        raise RuntimeError(
            'No SECRET_KEY set. Please set SECRET_KEY environment variable or add SECRET_KEY to instance/config.py'
        )
    config['SECRET_KEY'] = secret_key

    # VULNCHECK_API_TOKEN from environment or config file
    vulncheck = os.environ.get('VULNCHECK_API_TOKEN')
    if not vulncheck:
        vulncheck = config.get('VULNCHECK_API_TOKEN')
    if vulncheck:
        config['VULNCHECK_API_TOKEN'] = vulncheck

    cachedir = config.get('CACHE_DIRECTORY', os.path.join(instance_path, 'cache'))
    beacon = config.get('CLOUDFLARE_BEACON', None)

    if config.get('TESTING', False):
        # for local development on pre-release vex-reader
        import sys
        sys.path.append(config.get('OVERRIDE_VEX_READER', ''))
        beacon = None

    # we can only import vex after we know whether we're in testing mode or not
    from vex import Vex, VexPackages, NVD, CVE

    try:
        os.makedirs(instance_path)
    except OSError:
        pass

    # Ensure cache directories exist
    for subdir in ['cve', 'vex', 'nvd', 'epss', 'kev']:
        cache_subdir = os.path.join(cachedir, subdir)
        try:
            os.makedirs(cache_subdir, exist_ok=True)
        except OSError:
            pass

    # Setup templates and static files
    templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), 'templates'))
    app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), 'static')), name="static")

    # Add template filter
    def safe_getattr_filter(obj, attr, default='N/A'):
        """Safely get an attribute from an object"""
        if obj is None:
            return default
        return getattr(obj, attr, default)

    templates.env.filters['safe_getattr'] = safe_getattr_filter

    # Add url_path_for function to template globals for URL generation
    def url_path_for(route_name: str, **path_params):
        """Generate URL for a route (FastAPI equivalent of Flask's url_for)"""
        # Map route names to paths
        route_map = {
            'redirect_cve': '/cve',
            'home': '/',
        }
        path = route_map.get(route_name, '/')
        # Add path parameters if any
        if path_params:
            # For simple cases, just append to path
            # For more complex cases, you'd need to use FastAPI's url_path_for
            pass
        return path

    templates.env.globals['url_path_for'] = url_path_for

    # Add proxy fix middleware
    app.add_middleware(ProxyFixMiddleware, x_for=1, x_proto=1)

    @app.exception_handler(404)
    async def page_not_found(request: Request, exc):
        return templates.TemplateResponse("page_not_found.html", {"request": request}, status_code=404)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return templates.TemplateResponse("search.html", {"request": request})

    @app.post("/cve")
    async def redirect_cve_post(request: Request, cve: str = Form(...)):
        return RedirectResponse(url=f"/cve/{cve}", status_code=status.HTTP_302_FOUND)

    @app.get("/cve", response_class=HTMLResponse)
    async def redirect_cve_get(request: Request):
        return templates.TemplateResponse("cve_not_found.html", {"request": request}, status_code=404)

    @app.get("/cve/{cve}", response_class=HTMLResponse)
    async def render_cve(request: Request, cve: str):
        # Note: For production, consider adding response caching with a proper solution
        
        if not validate_cve_id(cve):
            response = templates.TemplateResponse("cve_not_valid.html", {"request": request, "cve": cve}, status_code=404)
            return response
        
        # Use async httpx client
        async with httpx.AsyncClient() as client:
            vex = await get_from_redhat(cachedir, Vex, cve, client)
        
        if not vex:
            response = templates.TemplateResponse("cve_not_found.html", {"request": request, "cve": cve}, status_code=404)
            return response
        
        packages = VexPackages(vex.raw)
        nvd, cve_obj, epss, kev = await get_all_data(cachedir, Vex, NVD, CVE, vex.cve, vulncheck)

        # Check if CVSS data exists before determining version
        has_cvss = has_cvss_data(vex, nvd, cve_obj)
        cvssVersion = determine_cvss_version(vex, nvd, cve_obj)
        
        # Apply CVSS version
        if cvssVersion == '3.1':
            nvd = nvd.cvss31 if nvd.cvss31.version else nvd.cvss30
            cve_obj = cve_obj.cvss31 if cve_obj.cvss31.version else cve_obj.cvss30
        elif cvssVersion == '3.0':
            nvd = nvd.cvss30
            cve_obj = cve_obj.cvss30
        else:  # 2.0
            nvd = nvd.cvss20
            cve_obj = cve_obj.cvss20

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

        context = {
            "request": request,
            "vex": vex,
            "nvd": nvd,
            "cve": cve_obj,
            "epss": epss,
            "cvssVersion": cvssVersion,
            "has_cvss": has_cvss,
            "fixdeltas": fixdeltas,
            "beacon": beacon,
            "kev": kev,
            "fixes": packages.fixes,
            "not_affected": not_affected,
            "wontfix": packages.wontfix,
            "affected": packages.affected,
            "mitigation": mitigation,
            "statement": statement,
            "description": description
        }

        return templates.TemplateResponse("cve.html", context)

    return app
