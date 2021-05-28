from flask import Flask, request, jsonify
from flask_mongoalchemy import MongoAlchemy


"""
Here are declared the models used by the database. They extend
the MongoAlchemy class 'Document' so they have all the query
related functions
"""

db = MongoAlchemy()


class User(db.Document):
    """
    Class to store the user information.
    """
    public_id = db.StringField()
    username = db.StringField()
    password = db.StringField()
    is_admin = db.BoolField()


class Brand(db.Document):
    """
    Class to store the brand information.
    """
    name = db.StringField()


class Phone(db.Document):
    """
    Class to store the phone information.
    """
    name = db.StringField()
    brand = db.DocumentField(Brand)
