from flask import Blueprint

main = Blueprint('main', __name__)  # main:蓝本的名称， __name__：蓝本所在的包或者模块

from . import views, errors   # 相对导入 .表示当前包  ..表示当前包的上一层
from ..models import Permission


# 9.3 上下文处理器，把Permission类加入模板上下文,便可让模板访问
@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)
