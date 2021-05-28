import datetime
import uuid
from functools import wraps
from flask import Flask, request, make_response
from models import db, User, Brand, Phone
from bson.json_util import dumps
from util import wrap_result
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['MONGOALCHEMY_DATABASE'] = 'phone-crud'
app.config['MONGOALCHEMY_CONNECTION_STRING'] = 'mongodb://127.0.0.1:27017/phone-crud'
app.config['SECRET_KEY'] = 'secret'

db.init_app(app)


def token_required(admin_required=False):
    def real_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].replace("Bearer ", "")
            if not token:
                return dumps({'message': 'a valid token is missing'})
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
                current_user = User.query.filter_by(public_id=data['public_id']).first()
                if current_user is None:
                    return dumps({'message': 'user is invalid'})
                elif admin_required and not current_user.is_admin:
                    return dumps({'message': 'unprivileged user'})
            except:
                return dumps({'message': 'token is invalid'})
            return func(current_user, *args, **kwargs)

        return wrapper

    return real_decorator


"""
Login methods
"""


@app.route('/api/register', methods=['POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, is_admin=False)
    new_user.save()

    return dumps({'message': 'registered successfully'})


@app.route('/api/login', methods=['POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = User.query.filter_by(username=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        return dumps({'token': token})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


"""
Brand methods
"""


@app.route("/api/brand", methods=['GET'])
@token_required(admin_required=True)
def list_brand(current_user):
    result = wrap_result(Brand.query.all())
    return dumps(result)


@app.route("/api/brand", methods=['POST'])
@token_required(admin_required=True)
def create_brand(current_user):
    name = request.json['name']
    brand = Brand(name=name)
    brand.save()
    return dumps({'message': 'saved successfully'})


@app.route("/api/brand/<_id>", methods=['PUT'])
@token_required(admin_required=True)
def update_brand(_id, current_user):
    name = request.json['name']
    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    brand.name = name
    brand.save()
    return dumps({'message': 'updated successfully'})


@app.route("/api/brand/<_id>", methods=['DELETE'])
@token_required(admin_required=True)
def remove_brand(_id, current_user):
    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    brand.remove()
    return dumps({'message': 'deleted successfully'})


"""
Phone methods
"""


@app.route("/api/phone", methods=['GET'])
@token_required()
def list_phone(current_user):
    result = wrap_result(Phone.query.all())
    return dumps(result)


@app.route("/api/phone", methods=['POST'])
@token_required()
def create_phone(current_user):
    name = request.json['name']
    brand_name = request.json['brandName']
    brand = Brand.query.filter(Brand.name == brand_name).first()
    phone = Phone(name=name, brand=brand)
    phone.save()
    return dumps({'message': 'saved successfully'})


@app.route("/api/phone/<_id>", methods=['PUT'])
@token_required()
def update_phone(_id, current_user):
    name = request.json['name']
    brand_name = request.json['brandName']
    brand = Brand.query.filter(Brand.name == brand_name).first()
    phone = Phone.query.filter(Phone.mongo_id == _id).first()
    phone.name = name
    phone.brand = brand
    phone.save()
    return dumps({'message': 'updated successfully'})


@app.route("/api/phone/<_id>", methods=['DELETE'])
@token_required()
def remove_phone(_id, current_user):
    phone = Phone.query.filter(Phone.mongo_id == _id).first()
    phone.remove()
    return dumps({'message': 'deleted successfully'})


app.run()
