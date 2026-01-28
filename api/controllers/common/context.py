import contextvars
from typing import Optional
import logging
from pydantic import BaseModel, Field
from flask import request

from core.errors.error import GreeTokenExpiredError
from extensions.ext_redis import redis_client
from libs.token import extract_gree_token_from_cookie
from models.engine import db
from services.gree_sso import get_user_info, get_redis_key, UserInfo
from models.account import (
    Account
)

logger = logging.getLogger(__name__)


class ArgumentInfo(BaseModel):
    gree_mail: Optional[str] = Field(default=None)
    gree_token: Optional[str] = Field(default=None)
    argument: Optional[str] = Field(default="Please set the argument in the cookies.")


# request_context = contextvars.ContextVar('request_context')
request_context: contextvars.ContextVar[ArgumentInfo] = contextvars.ContextVar('request_context')


#  存储上下文信息
# def set_content(gree_mail: str, gree_token: str, argument: str) -> None:
#     request_context.set({
#         'gree_mail': gree_mail,
#         'gree_token': gree_token,
#         'argument': argument
#     })

#  存储上下文信息
def set_content(
    gree_mail: Optional[str] = None,
    gree_token: Optional[str] = None,
    argument: Optional[str] = None,
) -> None:
    try:
        info = request_context.get()
    except LookupError:
        info = ArgumentInfo()
    if gree_mail is not None:
        info.gree_mail = gree_mail
    if gree_token is not None:
        info.gree_token = gree_token
    if argument is not None:
        info.argument = argument
    request_context.set(info)


#  根据参数名字获取
# def get_content() -> ArgumentInfo:
#     arg_info = ArgumentInfo()
#
#     argument = request_context.get("argument")
#     gree_mail = request_context.get("gree_mail")
#     gree_token = request_context.get("gree_token")
#     if argument is None:
#         argument = 'Please set the argument in the cookies.'
#     arg_info.argument = argument
#     if gree_token:
#         user_info = get_user_info(gree_token)
#         if user_info:
#             gree_mail = user_info.OpenID
#             arg_info.gree_mail = gree_mail
#             arg_info.gree_token = gree_token
#         else:
#             raise GreeTokenExpiredError(f"token 已经过期，请重新登陆")
#     else:
#         gree_token_cookie = extract_gree_token_from_cookie(request)
#         if gree_token_cookie:
#             user_info_cookie = get_user_info(gree_token_cookie)
#             if user_info_cookie:
#                 gree_mail_cookie = user_info_cookie.OpenID
#                 arg_info.gree_mail = gree_mail_cookie
#                 arg_info.gree_token = gree_token_cookie
#             else:
#                 raise GreeTokenExpiredError(f"token 已经过期，请重新登陆")
#         else:
#             db_mail = get_gree_mail_by_ip()
#             if not db_mail:
#                 raise GreeTokenExpiredError(f"用户信息过期，请重新登录")
#             redis_key = get_redis_key(db_mail)
#             user_info_json = redis_client.get(redis_key)
#             user_info = UserInfo.model_validate_json(user_info_json)
#             if user_info:
#                 arg_info.gree_mail = user_info.OpenID
#                 arg_info.gree_token = user_info.Token
#             else:
#                 arg_info.gree_mail = ""
#                 arg_info.gree_token = ""
#     return arg_info

#  获取上下文信息


def get_content() -> ArgumentInfo:
    try:
        info = request_context.get()
    except LookupError:
        info = ArgumentInfo()

    user_info: Optional[UserInfo] = None

    if info.gree_token:
        user_info = get_user_info(info.gree_token)
    if not user_info:
        info.gree_token = extract_gree_token_from_cookie(request)
        user_info = get_user_info(info.gree_token)

    if not user_info:
        db_mail = get_gree_mail_by_ip()
        if not db_mail:
            raise GreeTokenExpiredError(f"用户信息过期，请重新登录")
        user_info = get_redis_user_info(db_mail)
        if not user_info:
            raise GreeTokenExpiredError(f"用户信息过期，请重新登录")

    if user_info:
        info.gree_mail = user_info.OpenID
        info.gree_token = user_info.Token
    else:
        info.gree_mail = ""
        info.gree_token = ""
    return info


def get_redis_user_info(db_mail) -> Optional[UserInfo]:
    if not db_mail:
        return None
    try:
        redis_key = get_redis_key(db_mail)
        user_info_json = redis_client.get(redis_key)
        if not user_info_json:
            return None
        return UserInfo.model_validate_json(user_info_json)
    except Exception as e:
        print(f"Redis 获取用户信息失败(mail={db_mail}):{e}")
        return None


#         首先要去cookie中获取这些参数，没有的情况下采取通过ip绑定查询


#  为了方便维护把用户相关的接口写在一起了（迭代频率大）
def get_gree_mail_by_ip() -> str:
    ip = request.remote_addr
    forwarded_ip = request.headers.get('X-Forwarded-For')
    if forwarded_ip:
        ip = forwarded_ip.split(',')[0].split()
    email = db.session.query(Account.email).filter_by(last_login_ip=ip).first()
    if email:
        email_str = email[0]
        result = email_str.split("@")[0]
        return result
