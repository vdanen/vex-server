from flask import Flask, render_template, request, redirect, url_for
import os
from vex import Vex

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
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
        vexfile = f'{vexdir}/{year}/{cve}.json'
        if not os.path.exists(vexfile):
            return render_template('page_not_found.html'), 404

        vex = Vex(vexfile)
        return render_template('cve.html', vex=vex)

    return app
