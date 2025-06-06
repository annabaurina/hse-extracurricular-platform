from flask import Blueprint
from models import db, User  # Импортируем из models

bp = Blueprint('main', __name__)

@bp.route('/')
def home():
    return "Главная страница"