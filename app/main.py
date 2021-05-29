import datetime
import uuid
from functools import wraps
from flask import Flask, request
from constants import *
from models import db, User, Brand, Phone
from responses import *
from util import wrap_result
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

from validations import validate_password, check_parameter

app = Flask(__name__)
app.config[MONGOALCHEMY_DATABASE] = 'phone-crud'
app.config[MONGOALCHEMY_CONNECTION_STRING] = 'mongodb://127.0.0.1:27017/phone-crud'
app.config[SECRET_KEY] = 'jWu74U$F<.W(*PSs'

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
                return UnauthorizedResponse('a valid token is missing').make()
            try:
                # Try to decode the given token, if there is an error, return an exception
                data = jwt.decode(token, app.config[SECRET_KEY], algorithms="HS256")
                current_user = User.query.filter_by(public_id=data[PUBLIC_ID]).first()
                if current_user is None:
                    return UnauthorizedResponse('user is invalid').make()
                # check if the user has enough privileges
                elif admin_required and not current_user.is_admin:
                    return UnauthorizedResponse('unprivileged user').make()
            except:
                return UnauthorizedResponse('token is invalid').make()

            return func(*args, **kwargs)

        return wrapper

    return real_decorator


@app.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Headers', 'x-csrf-token')
        response.headers.add('Access-Control-Allow-Methods',
                             'GET, POST, OPTIONS, PUT, PATCH, DELETE')
        if origin:
            response.headers.add('Access-Control-Allow-Origin', origin)
    else:
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        if origin:
            response.headers.add('Access-Control-Allow-Origin', origin)

    return response


@app.before_first_request
def before_first_request():
    if User.query.count() == 0:
        # For testing purposes only:
        # Check if there are users in the database, if not, create a default admin account
        user = User(
            username="admin",
            password=generate_password_hash("password", method='sha256'),
            public_id=str(uuid.uuid4()),
            is_admin=True)
        user.save()


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
        return BadRequestResponse('Invalid payload').make()

    # hash the password to store it later
    hashed_password = generate_password_hash(data[PASSWORD], method='sha256')

    # create a new User with a random public_id, the given name and the hashed password
    new_user = User(public_id=str(uuid.uuid4()), username=data[USERNAME], password=hashed_password, is_admin=False)
    new_user.save()

    return SuccessResponse('registered successfully').make()


@app.route('/api/login', methods=['POST'])
def login_user():
    """
    Function to check the user credentials. If they are correct, then generate a valid JWT token
    and return it.
    :return: status of the request or the user token
    """

    # if the request doesn't have a Basic Authentication header, then discard it
    if not check_parameter(request.json, USERNAME) or not check_parameter(request.json, PASSWORD):
        return UnauthorizedResponse('could not verify').make()

    username = request.json[USERNAME]
    password = request.json[PASSWORD]

    # filter the user by the given username
    user = User.query.filter_by(username=username).first()
    if user is not None:
        # check if the hash of the given password matches the user stored one
        if check_password_hash(user.password, password):
            token = jwt.encode(
                {PUBLIC_ID: user.public_id, EXP: datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                app.config[SECRET_KEY])
            return DataResponse({TOKEN: token}).make()

    return UnauthorizedResponse('could not verify').make()


"""
Brand methods
"""


@app.route("/api/brand", methods=['GET'])
@token_required(admin_required=True)
def list_brand():
    """
    Lists all the brands with a pagination filter
    :return: Status of the request
    """
    # query the Brand model with no filter and return the data wrapped

    page = request.args.get(PAGE, 1, type=int)
    rows = request.args.get(ROWS, ROWS_PER_PAGE, type=int)
    ids_param = request.args.get(IDS, "", type=str)
    if len(ids_param) > 0:
        ids = ids_param.split(",")
        results = []
        for _id in ids:
            brand = Brand.query.filter(Brand.mongo_id == _id).first()
            if brand is not None:
                results.append(brand.to_json())
        return DataResponse({RESULTS: results, TOTAL: len(results)}).make()

    else:
        result = wrap_result(Brand.query.paginate(page=page, per_page=rows).items)
        return DataResponse({RESULTS: result, TOTAL: Brand.query.count()}).make()


@app.route("/api/brand/<_id>", methods=['GET'])
@token_required()
def get_brand(_id):
    """
    Lists the brand info based on the given id

    :param _id: Brand id to be queried
    :return: All the phone records
    """

    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    if brand is not None:
        return DataResponse({RESULTS: brand.to_json()}).make()
    else:
        return BadRequestResponse('Invalid payload').make()


@app.route("/api/brand", methods=['POST'])
@token_required(admin_required=True)
def create_brand():
    """
    Creates a new brand with the given info

    :return: Status of the request
    """
    if not check_parameter(request.json, NAME, 2, 15):
        return BadRequestResponse('Invalid payload').make()

    name = request.json[NAME]
    brand = Brand.query.filter(Brand.name == name).first()
    if brand is not None:
        return BadRequestResponse('Existing brand').make()

    # retrieve the brand name from the request, create a new Brand object and save it
    brand = Brand(name=name)
    brand.save()
    return DataResponse({RESULTS: brand.to_json()}).make()


@app.route("/api/brand/<_id>", methods=['PUT'])
@token_required(admin_required=True)
def update_brand(_id):
    """
    Updates the information of the given Brand.

    :param _id: Identifier of the brand
    :return: Status of the request
    """

    if not check_parameter(request.json, NAME, 2, 15):
        return BadRequestResponse('Invalid payload').make()

    name = request.json[NAME]
    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    if brand is None:
        return BadRequestResponse('Brand does not exist').make()
    brand.name = name
    brand.save()
    phones = Phone.query.filter(Phone.brand.mongo_id == _id).all()
    for phone in phones:
        phone.brand = brand
        phone.save()
    return SuccessResponse('updated successfully').make()


@app.route("/api/brand/<_id>", methods=['DELETE'])
@token_required(admin_required=True)
def remove_brand(_id):
    """
    Removes the document of the given Brand.

    :param _id: Identifier of the brand
    :return: Status of the request
    """
    brand = Brand.query.filter(Brand.mongo_id == _id).first()
    if brand is None:
        return BadRequestResponse('Brand does not exist').make()
    brand.remove()
    return SuccessResponse('deleted successfully').make()


@app.route("/api/brand", methods=['DELETE'])
@token_required(admin_required=True)
def remove_brands():
    """
    Removes the document of the given Brand.

    :param _id: Identifier of the brand
    :return: Status of the request
    """
    ids_param = request.args.get(IDS, "", type=str)
    ids = ids_param.split(",")
    for _id in ids:
        brand = Brand.query.filter(Brand.mongo_id == _id).first()
        if brand is not None:
            brand.remove()
    return SuccessResponse('deleted successfully').make()


"""
Phone methods
"""


@app.route("/api/phone", methods=['GET'])
@token_required()
def list_phone():
    """
    Lists all the phone records on the database with a pagination filter

    :return: All the phone records
    """

    page = request.args.get(PAGE, 1, type=int)
    rows = request.args.get(ROWS, ROWS_PER_PAGE, type=int)

    result = wrap_result(Phone.query.paginate(page=page, per_page=rows).items)
    return DataResponse({RESULTS: result, TOTAL: Phone.query.count()}).make()


@app.route("/api/phone/<_id>", methods=['GET'])
@token_required()
def get_phone(_id):
    """
    Lists the phone info based on the given id

    :param _id: Phone id to be queried
    :return: All the phone records
    """

    phone = Phone.query.filter(Phone.mongo_id == _id).first()
    if phone is not None:
        return DataResponse({RESULTS: phone.to_json()}).make()
    else:
        return BadRequestResponse('Invalid payload').make()


@app.route("/api/phone", methods=['POST'])
@token_required()
def create_phone():
    """
    Creates a new Phone record on the database. First, checks if the given brand
    exists. If the brand does not exist, return an error

    :return: Status of the request
    """

    if not check_parameter(request.json, NAME, 2, 15) \
            or not check_parameter(request.json, BRAND) \
            or not check_parameter(request.json[BRAND], ID):
        return BadRequestResponse('Invalid payload').make()

    name = request.json[NAME]
    brand_id = request.json[BRAND][ID]
    brand = Brand.query.filter(Brand.mongo_id == brand_id).first()
    if brand is None:
        return BadRequestResponse('Brand does not exist').make()

    phone = Phone(name=name, brand=brand)
    phone.save()
    return DataResponse({RESULTS: phone.to_json()}).make()


@app.route("/api/phone/<_id>", methods=['PUT'])
@token_required()
def update_phone(_id):
    """
    Updates the information of the phone

    :param _id: Phone id to be modified
    :return: Status of the request
    """

    name = request.json[NAME]
    if not check_parameter(request.json, NAME, 2, 15) \
            or not check_parameter(request.json, BRAND) \
            or not check_parameter(request.json[BRAND], ID, 2, 30):
        return BadRequestResponse('Invalid payload').make()

    name = request.json[NAME]
    brand_id = request.json[BRAND][ID]
    brand = Brand.query.filter(Brand.mongo_id == brand_id).first()
    phone = Phone.query.filter(Phone.mongo_id == _id).first()

    if brand is None or phone is None:
        return BadRequestResponse('One of the elements does not exist').make()

    phone.name = name
    phone.brand = brand
    phone.save()
    return DataResponse({RESULTS: phone.to_json()}).make()


@app.route("/api/phone/<_id>", methods=['DELETE'])
@token_required()
def remove_phone(_id):
    """
    Deletes the phone entry from the database

    :param _id:
    :return:
    """
    phone = Phone.query.filter(Phone.mongo_id == _id).first()
    if phone is None:
        return BadRequestResponse('Phone does not exist').make()

    phone.remove()
    return SuccessResponse('Deleted successfully').make()


@app.route("/api/phone", methods=['DELETE'])
@token_required()
def remove_phones():
    """
    Deletes the phones entries from the database

    :param _id:
    :return:
    """
    ids_param = request.args.get(IDS, "", type=str)
    ids = ids_param.split(",")
    for _id in ids:
        phone = Phone.query.filter(Phone.mongo_id == _id).first()
        if phone is not None:
            phone.remove()
    return SuccessResponse('Deleted successfully').make()


app.run()