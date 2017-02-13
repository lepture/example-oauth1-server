# coding: utf-8

from flask import Flask
from flask import session, request
from flask import render_template, redirect
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from flask_oauthlib.provider import OAuth1Provider


app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)

app.config.update({
    'OAUTH1_PROVIDER_ENFORCE_SSL': False,
    'OAUTH1_PROVIDER_KEY_LENGTH': (10, 100),
})
oauth = OAuth1Provider(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)


class Client(db.Model):
    client_key = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), index=True, nullable=False)

    # creator of the client
    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')
    _realms = db.Column(db.Text)
    _redirect_uris = db.Column(db.Text)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_realms(self):
        if self._realms:
            return self._realms.split()
        return []


class RequestToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_key = db.Column(
        db.String(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = db.relationship('Client')

    token = db.Column(db.String(255), index=True, unique=True)
    secret = db.Column(db.String(255), nullable=False)

    verifier = db.Column(db.String(255))

    redirect_uri = db.Column(db.Text)
    _realms = db.Column(db.Text)

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


class Nonce(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.Integer)
    nonce = db.Column(db.String(40))
    client_key = db.Column(
        db.String(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = db.relationship('Client')
    request_token = db.Column(db.String(50))
    access_token = db.Column(db.String(50))


class AccessToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_key = db.Column(
        db.String(40), db.ForeignKey('client.client_key'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id'),
    )
    user = db.relationship('User')

    token = db.Column(db.String(255))
    secret = db.Column(db.String(255))

    _realms = db.Column(db.Text)

    @property
    def realms(self):
        if self._realms:
            return self._realms.split()
        return []


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


@app.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)


@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_key=gen_salt(40),
        client_secret=gen_salt(50),
        _redirect_uris='http://127.0.0.1:8000/authorized',
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_key=item.client_key,
        client_secret=item.client_secret
    )


@oauth.clientgetter
def load_client(client_key):
    return Client.query.get(client_key)


@oauth.grantgetter
def load_request_token(token):
    return RequestToken.query.filter_by(token=token).first()


@oauth.grantsetter
def save_request_token(token, request):
    if hasattr(oauth, 'realms') and oauth.realms:
        realms = ' '.join(request.realms)
    else:
        realms = None
    grant = RequestToken(
        token=token['oauth_token'],
        secret=token['oauth_token_secret'],
        client=request.client,
        redirect_uri=request.redirect_uri,
        _realms=realms,
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.verifiergetter
def load_verifier(verifier, token):
    return RequestToken.query.filter_by(
        verifier=verifier, token=token
    ).first()


@oauth.verifiersetter
def save_verifier(token, verifier, *args, **kwargs):
    tok = RequestToken.query.filter_by(token=token).first()
    tok.verifier = verifier['oauth_verifier']
    tok.user = current_user()
    db.session.add(tok)
    db.session.commit()
    return tok


@oauth.noncegetter
def load_nonce(client_key, timestamp, nonce, request_token, access_token):
    return Nonce.query.filter_by(
        client_key=client_key, timestamp=timestamp, nonce=nonce,
        request_token=request_token, access_token=access_token,
    ).first()


@oauth.noncesetter
def save_nonce(client_key, timestamp, nonce, request_token, access_token):
    nonce = Nonce(
        client_key=client_key,
        timestamp=timestamp,
        nonce=nonce,
        request_token=request_token,
        access_token=access_token,
    )
    db.session.add(nonce)
    db.session.commit()
    return nonce


@oauth.tokengetter
def load_access_token(client_key, token, *args, **kwargs):
    return AccessToken.query.filter_by(
        client_key=client_key, token=token
    ).first()


@oauth.tokensetter
def save_access_token(token, request):
    tok = AccessToken(
        client=request.client,
        user=request.user,
        token=token['oauth_token'],
        secret=token['oauth_token_secret'],
        _realms=token['oauth_authorized_realms'],
    )
    db.session.add(tok)
    db.session.commit()


@app.route('/oauth/request_token')
@oauth.request_token_handler
def request_token():
    return {}


@app.route('/oauth/access_token')
@oauth.access_token_handler
def access_token():
    return {}


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_key = kwargs.get('resource_owner_key')
        client = Client.query.filter_by(client_key=client_key).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)
    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@app.route('/api/me')
@oauth.require_oauth()
def me(req):
    user = req.user
    return jsonify(username=user.username)


import logging
logger = logging.getLogger('flask_oauthlib')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)


if __name__ == '__main__':
    db.create_all()
    app.run()
