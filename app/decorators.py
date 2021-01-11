from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission


# 检查常规权限装饰器
def permission_required(permission):
    def decorator(f):
        @wraps(f)  # 不改变使用装饰器原有函数的结果
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# 检查管理员权限装饰器
def admin_required(f):
    return permission_required(Permission.ADMIN)(f)
