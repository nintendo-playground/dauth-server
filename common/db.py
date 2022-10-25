
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
session = db.session


class ClientID(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	client_id = db.Column(db.String, unique=True, nullable=False)
	client_key = db.Column(db.String)
	name = db.Column(db.String)


class Ban(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	device_id = db.Column(db.String, nullable=False)
	permanent = db.Column(db.Boolean, nullable=False, default=True)
	start = db.Column(db.DateTime)
	end = db.Column(db.DateTime)
	reason = db.Column(db.String)


def init_app(app):
	db.init_app(app)
