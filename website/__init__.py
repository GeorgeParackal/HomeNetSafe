from os import path

from flask import Flask 
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    from .views import views

    app.register_blueprint(views, url_prefix='/')

    return app
