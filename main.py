import datetime
import uuid
from functools import wraps
from flask import Flask, request, make_response
from constants import *
from models import db, User, Brand, Phone
from bson.json_util import dumps
from util import wrap_result
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

from validations import validate_password, check_parameter

app = Flask(__name__)
app.config[MONGOALCHEMY_DATABASE] = 'phone-crud'
app.config[MONGOALCHEMY_CONNECTION_STRING] = 'mongodb://127.0.0.1:27017/phone-crud'
app.config[SECRET_KEY] = 'secret'

db.init_app(app)


def token_required(admin_required=False):
    """
    Decorator to simplify the user validation process. It checks for the headers of the request,
    specifically the 'Authorization' one. Then, validates the header token with the User
    model.

    If optional parameter 'admin_required' is given, it checks if the user has enough
    privileges.

    :param admin_required:
    :return:
    """
    def real_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = None
            if AUTHORIZATION in request.headers:
                token = request.headers[AUTHORIZATION].replace(BEARER_REPLACE, "")
            if not token:
                # No token given, return an error
                return dumps({'message': 'a valid token is missing'})
            try:
                # Try to decode the given token, if there is an error, return an exception
                data = jwt.decode(token, app.config[SECRET_KEY], algorithms="HS256")
                current_user = User.query.filter_by(public_id=data[PUBLIC_ID]).first()
                if current_user is None:
                    return dumps({'message': 'user is invalid'})
                # check if the user has enough privileges
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
    """
    Function to register a user in the database. Takes the input data and stores it, the
    password field is hashed so it could not be retrieved in case of database dump
    :return: Status message of the request
    """
    data = request.get_json()

    # check for the needed parameters
    if not validate_password(data) or not check_parameter(data, USERNAME, 4, 16):
        return make_response(dumps({"message": "Invalid payload"}), 401)

    # hash the password to store it later
    hashed_password = generate_password_hash(data[PASSWORD], method='sha256')

    # create a new User with a random public_id, the given name and the hashed password
    new_user = User(public_id=str(uuid.uuid4()), username=data[USERNAME], password=hashed_password, is_admin=False)
    new_user.save()

    return dumps({'message': 'registered successfully'})


@app.route('/api/login', methods=['POST'])
def login_user():
    """
    Function to check the user credentials. If they are correct, then generate a valid JWT token
    and return it.
    :return: status of the request or the user token
    """
    auth = request.authorization

    # if the request doesn't have a Basic Authentication header, then discard it
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    # filter the user by the given username
    user = User.query.filter_by(username=auth.username).first()

    # check if the hash of the given password matches the user stored one
    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {PUBLIC_ID: user.public_id, EXP: datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config[SECRET_KEY])
        return dumps({TOKEN: token})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


"""
Brand methods
"""


@app.route("/api/brand", methods=['GET'])
@token_required(admin_required=True)
def list_brand(current_user):
    """
    Lists all the brands with no filter
    TODO make a pagination system
    :param current_user: The user who makes the call
    :return: Status of the request
    """
    # query the Brand model with no filter and return the data wrapped
    result = wrap_result(Brand.query.all())
    return dumps(result)


@app.route("/api/brand", methods=['POST'])
@token_required(admin_required=True)
def create_brand(current_user):
    """
    Creates a new brand with the given info

    :param current_user: The user who makes the call
    :return: Status of the request
    """
    if not check_parameter(request.json, NAME, 2, 15):
        return dumps({'message': 'Invalid payload'})

    name = request.json[NAME]
    brand = Brand.query.filter(Brand.name == name).first()
    if brand is not None:
        return dumps({'message': 'Existing brand'})

    # retrieve the brand name from the request, create a new Brand object and save it
    brand = Brand(name=name)
    brand.save()
    return dumps({'message': 'saved successfully'})


@app.route("/api/brand/<_id>", methods=['PUT'])
@token_required(admin_required=True)
def update_brand(_id, current_user):
    """
    Updates the information of the given Brand.

    :param _id: Identifier of the brand
    :param current_user: The user who makes the call
    :return: Status of the request
    """

    if not check_parameter(request.json, NAME, 2, 15):
        return dumps({'message': 'Invalid payload'})

    name = request.json[NAME]
    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    if brand is None:
        return dumps({'message': 'Brand does not exist'})
    brand.name = name
    brand.save()
    return dumps({'message': 'updated successfully'})


@app.route("/api/brand/<_id>", methods=['DELETE'])
@token_required(admin_required=True)
def remove_brand(_id, current_user):
    """
    Removes the document of the given Brand.

    :param _id: Identifier of the brand
    :param current_user: The user who makes the call
    :return: Status of the request
    """
    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    if brand is None:
        return dumps({'message': 'Brand does not exist'})
    brand.remove()
    return dumps({'message': 'deleted successfully'})


"""
Phone methods
"""


@app.route("/api/phone", methods=['GET'])
@token_required()
def list_phone(current_user):
    """
    Lists all the phone records on the database with no filter

    TODO implement a pagination system
    :param current_user: The user who makes the call
    :return: All the phone records
    """
    result = wrap_result(Phone.query.all())
    return dumps(result)


@app.route("/api/phone", methods=['POST'])
@token_required()
def create_phone(current_user):
    """
    Creates a new Phone record on the database. First, checks if the given brand
    exists. If the brand does not exist, return an error

    :param current_user: The user who makes the call
    :return: Status of the request
    """

    if not check_parameter(request.json, NAME, 2, 15) or not check_parameter(request.json, BRAND_NAME, 2, 15):
        return dumps({'message': 'Invalid payload'})

    name = request.json[NAME]
    brand_name = request.json[BRAND_NAME]
    brand = Brand.query.filter(Brand.name == brand_name).first()
    if brand is None:
        return dumps({'message': 'Brand does not exist'})

    phone = Phone(name=name, brand=brand)
    phone.save()
    return dumps({'message': 'saved successfully'})


@app.route("/api/phone/<_id>", methods=['PUT'])
@token_required()
def update_phone(_id, current_user):
    """
    Updates the information of the phone

    TODO check if the information if valid
    :param _id: Phone id to be modified
    :param current_user: The user who makes the call
    :return: Status of the request
    """
    name = request.json[NAME]
    brand_name = request.json[BRAND_NAME]
    if not check_parameter(request.json, NAME, 2, 15) or not check_parameter(request.json, BRAND_NAME, 2, 15):
        return dumps({'message': 'Invalid payload'})

    brand = Brand.query.filter(Brand.name == brand_name).first()
    phone = Phone.query.filter(Phone.mongo_id == _id).first()

    if brand is None or phone is None:
        return dumps({'message': 'One of the elements does not exist'})

    phone.name = name
    phone.brand = brand
    phone.save()
    return dumps({'message': 'updated successfully'})


@app.route("/api/phone/<_id>", methods=['DELETE'])
@token_required()
def remove_phone(_id, current_user):
    """
    Deletes the phone entry from the database

    :param _id:
    :param current_user:
    :return:
    """
    phone = Phone.query.filter(Phone.mongo_id == _id).first()
    if phone is None:
        return dumps({'message': 'Phone does not exist'})

    phone.remove()
    return dumps({'message': 'deleted successfully'})


app.run()
