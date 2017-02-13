# coding: utf-8

from flask import Flask, session, url_for, request, jsonify
from flask_oauthlib.client import OAuth


app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'

# TODO: fill them
CLIENT_KEY = ''
CLIENT_SECRET = ''

oauth = OAuth(app)
remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_KEY,
    consumer_secret=CLIENT_SECRET,
    base_url='http://127.0.0.1:5000/api/',
    request_token_url='http://127.0.0.1:5000/oauth/request_token',
    access_token_method='GET',
    access_token_url='http://127.0.0.1:5000/oauth/access_token',
    authorize_url='http://127.0.0.1:5000/oauth/authorize',
)


@app.route('/')
def home():
    if 'example_oauth' in session:
        resp = remote.get('me')
        return jsonify(resp.data)
    return remote.authorize(callback=url_for('authorized', _external=True))


@app.route('/authorized')
@remote.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: error=%s' % (
            request.args['error']
        )
    if 'oauth_token' in resp:
        session['example_oauth'] = resp
        return jsonify(resp)
    return str(resp)


@remote.tokengetter
def example_oauth_token():
    if 'example_oauth' in session:
        resp = session['example_oauth']
        return resp['oauth_token'], resp['oauth_token_secret']


import logging
logger = logging.getLogger('flask_oauthlib')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


if __name__ == '__main__':
    app.run(port=8000)
