from flask import Flask, request, jsonify
from flask_mongoalchemy import MongoAlchemy


db = MongoAlchemy()


class User(db.Document):
    public_id = db.IntField()
    username = db.StringField()
    password = db.StringField()


class Brand(db.Document):
    name = db.StringField()


class Phone(db.Document):
    name = db.StringField()
    brand = db.DocumentField(Brand)
