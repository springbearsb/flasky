from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from config import config
from flask_login import LoginManager
from flask_pagedown import PageDown


# 创建对象
bootstrap = Bootstrap()  # 前端框架
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()


# 初始化Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # login_view用于设置登录页面的端点


# 应用包的构造文件
def create_app(config_name):
    """
    create_app() 函数是应用的工厂函数，接受一个参数，
    是应用使用的配置名
    """
    app = Flask(__name__)  # 初始化Flask的程序实例app
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    # 初始化Flask-Login,用于用户注册
    login_manager.init_app(app)
    # 初始化Flask-PageDown
    pagedown.init_app(app)

    # 注册主蓝本，从本级目录下的main文件夹中引入main作为main_blueprint蓝本
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)  # 注册蓝图
    # 注册身份验证蓝本
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')  # 注册后的路由加上指定前缀：/auth
    # 14 注册API蓝本
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api/v1')

    return app
