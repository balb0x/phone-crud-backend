from flask_mongoalchemy import MongoAlchemy
from mongoalchemy.exceptions import MissingValueException, FieldNotRetrieved

"""
Here are declared the models used by the database. They extend
the MongoAlchemy class 'Document' so they have all the query
related functions
"""

db = MongoAlchemy()


class BaseDocument(db.Document):
    """
    Class to extend the base functions of the Document class
    """

    def to_json(self):
        ''' Returns a transformation of this document into a form suitable to
            be sent thought an API server.  This is done by using the ``wrap()``
            methods of the underlying fields to set values.'''
        res = {}
        cls = self.__class__
        for name in self.get_fields():
            field = getattr(cls, name)
            try:
                value = getattr(self, name)
                if isinstance(value, BaseDocument):
                    res[field.db_field] = value.to_json()
                elif field.db_field == '_id':
                    res["id"] = str(field.wrap(value))
                else:
                    res[field.db_field] = field.wrap(value)
            except AttributeError as e:
                if field.required:
                    raise MissingValueException(name)
            except FieldNotRetrieved as fne:
                if field.required:
                    raise
        return res


class User(BaseDocument):
    """
    Class to store the user information.
    """
    public_id = db.StringField()
    username = db.StringField()
    password = db.StringField()
    is_admin = db.BoolField()


class Brand(BaseDocument):
    """
    Class to store the brand information.
    """
    name = db.StringField()
    country = db.StringField()
    year = db.IntField()
    ceo = db.StringField()
    entry = db.IntField()
    isin = db.StringField()


class Phone(BaseDocument):
    """
    Class to store the phone information.
    """
    name = db.StringField()
    brand = db.DocumentField(Brand)
    so = db.StringField()
    water_proof = db.BoolField()
    h5g = db.BoolField()
    ram = db.IntField()