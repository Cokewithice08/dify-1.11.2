import contextvars
from pydantic import BaseModel
from flask import request

from core.errors.error import GreeTokenExpiredError
from extensions.ext_redis import redis_client
from libs.token import extract_gree_token_from_cookie
from models.engine import db
from services.gree_sso import get_user_info, get_redis_key, UserInfo
from models.account import (
    Account
)

request_context = contextvars.ContextVar('request_context')


class ArgumentInfo(BaseModel):
    gree_mail: str | None = None
    gree_token: str | None = None
    argument: str | None = None


#  存储上下文信息
def set_content(gree_mail: str, gree_token: str, argument: str) -> None:
    request_context.set({
        'gree_mail': gree_mail,
        'gree_token': gree_token,
        'argument': argument
    })


#  根据参数名字获取
def get_content() -> ArgumentInfo:
    arg_info = ArgumentInfo()

    argument = request_context.get("argument")
    gree_mail = request_context.get("gree_mail")
    gree_token = request_context.get("gree_token")
    if argument is None:
        argument = 'Please set the argument in the cookies.'
    arg_info.argument = argument
    if gree_token:
        user_info = get_user_info(gree_token)
        if user_info:
            gree_mail = user_info.OpenID
            arg_info.gree_mail = gree_mail
            arg_info.gree_token = gree_token
        else:
            raise GreeTokenExpiredError(f"token 已经过期，请重新登陆")
    else:
        gree_token_cookie = extract_gree_token_from_cookie(request)
        if gree_token_cookie:
            user_info_cookie = get_user_info(gree_token_cookie)
            if user_info_cookie:
                gree_mail_cookie = user_info_cookie.OpenID
                arg_info.gree_mail = gree_mail_cookie
                arg_info.gree_token = gree_token_cookie
            else:
                raise GreeTokenExpiredError(f"token 已经过期，请重新登陆")
        else:
            db_mail = get_gree_mail_by_ip()
            if not db_mail:
                raise GreeTokenExpiredError(f"用户信息过期，请重新登录")
            redis_key = get_redis_key(db_mail)
            user_info_json = redis_client.get(redis_key)
            user_info = UserInfo.model_validate_json(user_info_json)
            if user_info:
                arg_info.gree_mail = user_info.OpenID
                arg_info.gree_token = user_info.Token
            else:
                arg_info.gree_mail = ""
                arg_info.gree_token = ""
    return arg_info


#         首先要去cookie中获取这些参数，没有的情况下采取通过ip绑定查询


#  为了方便维护把用户相关的接口写在一起了（迭代频率大）
def get_gree_mail_by_ip() -> str:
    ip = request.remote_addr
    forwarded_ip = request.headers.get('X-Forwarded-For')
    if forwarded_ip:
        ip = forwarded_ip.split(',')[0].split()
    email = db.session.query(Account.email).filter_by(last_login_ip=ip).first()
    if email:
        result = email.split("@")[0]
        return result
