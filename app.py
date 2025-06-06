# -*- coding: utf-8 -*-
from flask import Flask
from flask_login import LoginManager
from config import Config
from models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Инициализация расширений
    db.init_app(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'auth.login'
    
    with app.app_context():
        # Регистрация blueprint'ов
        from auth import auth_bp
        from routes import main_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(main_bp)
        
        # Создание таблиц БД
        db.create_all()
        
        # Настройка загрузчика пользователя
        from models import User
        
        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)