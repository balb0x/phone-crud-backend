from flask import make_response
from bson.json_util import dumps


class BaseResponse:
    """
    Base class to return in the API calls. It handles the
    return code and the return data
    """
    def __init__(self, code, data):
        self.code = code
        self.data = data

    def make(self):
        # Use flask to make the response with the data and the code
        return make_response(dumps(self.data), self.code)


class MessageResponse(BaseResponse):
    """
    Base class which extends BaseResponse class. It accepts a
    return code and a message, then it is handled in a json dictionary
    """
    def __init__(self, code, message):
        # Put the message string in a dictionary
        super().__init__(code, {'message': message})


class SuccessResponse(MessageResponse):
    """
    Class which extends MessageResponse. Returns a 200 code
    and accepts a simple message
    """
    def __init__(self, message):
        # Put the message string in a dictionary
        super().__init__(200, message)


class DataResponse(BaseResponse):
    """
    Class which extends BaseResponse, Returns a 200 code
    and the given dictionary
    """
    def __init__(self, data):
        super().__init__(200, data)


class BadRequestResponse(MessageResponse):
    """
    Class which extends MessageResponse. Returns a 400 code
    and accepts a simple message
    """
    def __init__(self, message):
        super().__init__(400, message)


class UnauthorizedResponse(MessageResponse):
    """
        Class which extends MessageResponse. Returns a 401 code
        and accepts a simple message
        """
    def __init__(self, message):
        super().__init__(401, message)


