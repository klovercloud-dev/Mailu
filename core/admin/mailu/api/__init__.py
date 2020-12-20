from flask import Blueprint

api = Blueprint('api', __name__)

from mailu.api.views import *