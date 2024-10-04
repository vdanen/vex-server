# vex-server
This is mostly a proof of concept to illustrate that VEX documents aren't
just the new shiny thing, but they're actually pretty darn functional.

It's a quick-and-dirty recreation of the Red Hat CVE pages using the NVD
API and the Red Hat VEX files that are located at
https://access.redhat.com/security/data/csaf/v2/vex/2024/

It uses my [vex-reader](https://pypi.org/project/vex-reader/) Python module
and shows CVE pages for Red Hat VEX documents using the Flask framework.
