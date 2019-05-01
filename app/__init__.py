from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
import io
from flask_restplus import Api, Resource, fields, Namespace

from flask_cors import CORS
import requests
import os
from .otstamp import TimeStamp

app = Flask(__name__)

auth = HTTPBasicAuth()
authorizations = {
        'token': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'token'}
        }

API_TITLE = os.environ['API_TITLE']
API_DESCRIPTION = os.environ['API_DESCRIPTION']

api = Api(app, version='1.1', title=API_TITLE,
            description=API_DESCRIPTION,
            authorizations=authorizations
            )

# Routes
import os
import jwt
from functools import wraps
from flask import make_response, jsonify
PUBLIC_KEY = os.environ['PUBLIC_KEY']
def requires_auth(roles):
    def requires_auth_decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            def decode_token(token):
                return jwt.decode(token.encode("utf-8"), PUBLIC_KEY, algorithms='RS256')
            try:
                decoded = decode_token(str(request.headers['Token']))
            except Exception as e:
                post_token = False
                if request.json != None:
                    if 'token' in request.json:
                        try:
                            decoded = decode_token(request.json.get('token'))
                            post_token=True
                        except Exception as e:
                            return make_response(jsonify({'message': str(e)}),401)
                if not post_token:
                    return make_response(jsonify({'message': str(e)}), 401)
            if set(roles).isdisjoint(decoded['roles']):
                return make_response(jsonify({'message': 'Not authorized for this endpoint'}),401)
            return f(*args, **kwargs)
        return decorated
    return requires_auth_decorator
ns_token = Namespace('test', description='Tests')
@ns_token.route('/auth/')
class ResourceRoute(Resource):
    @ns_token.doc('token_resource',security='token')
    @requires_auth(['user','moderator','admin'])
    def get(self):
        return jsonify({'message': 'Success'})
@ns_token.route('/')
class TestRoute(Resource):
    @ns_token.doc('resource',security='token')
    def get(self):
        return jsonify({'message': 'Success'})

ns_save = Namespace('timestamp', description='Timestamp')
save_model = ns_save.model("collection", {
    "url": fields.String(),
    })

@ns_save.route('/')
class SaveRoute(Resource):
    @ns_save.doc('save',security='token')
    @requires_auth(['moderator','admin'])
    @ns_save.expect(save_model)
    def post(self):
        url = request.get_json()['url']
        timestamp = TimeStamp(io.BytesIO(url.encode('utf-8')))
        print(timestamp)
        return 'woo' 


###
api.add_namespace(ns_token)
api.add_namespace(ns_save)

