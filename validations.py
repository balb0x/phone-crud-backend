def validate_password(data):
    """
    Validates the given password in a request data. First, checks if
    it exists, then check if the password has the necessary length
    :param data: Dict containing all the request data
    :return: Boolean determining the request has a valid password
    """

    if "password" not in data:
        return False
    password = data["password"]
    if 4 < len(password) < 16:
        return False

    return True


def check_parameter(data, parameter, min_length=None, max_length=None):
    """
    Check if the given parameter is the the data request. If max or min parameters
    are present, it checks for the parameter length

    :param data: Dict containing all the request data
    :param parameter: Key to search for
    :param min_length: Optional, min length of the parameter
    :param max_length: Optional, max length of the parameter
    :return:
    """

    if parameter not in data:
        return False

    if min_length is not None and len(data[parameter]) < min_length:
        return False

    if max_length is not None and len(data[parameter]) > max_length:
        return False

    return True
