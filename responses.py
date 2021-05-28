from flask import make_response
from bson.json_util import dumps


class BaseResponse:
    def __init__(self, code, data):
        self.code = code
        self.data = data

    def make(self):
        return make_response(dumps(self.data), self.code)


class MessageResponse(BaseResponse):
    def __init__(self, code, message):
        super().__init__(code, {'message': message})


class SuccessResponse(MessageResponse):
    def __init__(self, data):
        super().__init__(200, data)


class DataResponse(BaseResponse):
    def __init__(self, data):
        super().__init__(200, data)


class BadRequestResponse(MessageResponse):
    def __init__(self, message):
        super().__init__(400, message)


class UnauthorizedResponse(MessageResponse):
    def __init__(self, message):
        super().__init__(401, message)


