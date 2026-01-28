import json
import logging
from datetime import datetime
from decimal import Decimal

import requests
from flask import request
from pydantic import BaseModel

from core.errors.error import GreeTokenExpiredError
from libs.helper import extract_remote_ip
import models
from extensions.ext_redis import redis_client
from models import Conversation, Message
from models.engine import db
from sqlalchemy import func
from sqlalchemy.orm import Query

from .account_service import AccountService, RegisterService, TokenPair, TenantService

logger = logging.getLogger(__name__)
# 格力单点登录
GREE_SSO_URL_GET_TOKEN = 'http://wfserver.gree.com/sso/ssoapi/GetToken'
GREE_SSO_URL_GET_USER_INFO = 'http://wfserver.gree.com/sso/ssoapi/GetUserInfo'
GREE_SSO_SIGN_OUT = 'https://wfserver.gree.com/sso/ssoapi/SignOut'
GREE_SSO_APP_ID = '0347f117-1b67-46a1-b4ec-a173f7bffa14'
GREE_SSO_APP_KEY = '2ce5a8c1-3a99-4036-92cc-a8f434b1a17c'

# 测试环境使用如下
# GREE_SSO_APP_ID = '5f4e61c6-29a2-40b2-a62e-c99602dc1f30'
# GREE_SSO_APP_KEY = '9ab4a757-5bb1-474f-948e-44866d3e7ffe'


# redis key
GREE_REDIS_KEY = 'gree:user:mail:'


#系统登录页面
class TokenGree(BaseModel):
    access_token: str
    refresh_token: str
    csrf_token: str
    token: str
    mail: str
    workspace: bool


# chat页面登录页面
class TokenMailGree(BaseModel):
    mail: str
    token: str


# 用户数据
class UserInfo(BaseModel):
    Success: bool | None = None
    Message: str | None = None
    user_id: str | None = None
    OpenID: str | None = None
    AppAccount: str | None = None
    StaffID: str | None = None
    EmpID: str | None = None
    HREmpID: str | None = None
    OrgL1Alias: str | None = None
    OrgL1Name: str | None = None
    OrgL2Alias: str | None = None
    OrgL2Name: str | None = None
    OrgL3Alias: str | None = None
    OrgL3Name: str | None = None
    Job: str | None = None
    Token: str | None = None
    UserName: str | None = None
    DepartmentID: str | None = None
    DepartmentName: str | None = None
    CompanyID: str | None = None
    CompanyName: str | None = None
    Title: str | None = None
    Office: str | None = None
    InService: bool | None = None
    Phone: str | None = None
    OfficeLeader: str | None = None
    DeptLeader: str | None = None
    IP: str | None = None


# 调用接口返回的数据
class ResultInfo(BaseModel):
    Success: bool
    Message: str


# 根据callback获取token
def get_token(callback: str) -> ResultInfo:
    ip = request.remote_addr
    forwarded_ip = request.headers.get('X-Forwarded-For')
    if forwarded_ip:
        ip = forwarded_ip.split(',')[0].split()
    params = {
        'appid': GREE_SSO_APP_ID,
        'appkey': GREE_SSO_APP_KEY,
        'ip': ip,
        'callback': callback
    }
    response = requests.get(GREE_SSO_URL_GET_TOKEN, params=params)
    if response.status_code == 200:
        json_data = response.json()
        if 'Success' in json_data or 'Message' in json_data:
            json_data = ResultInfo(**json_data)
            logger.exception(json_data)
            return json_data


# 根据token查询用户信息
def get_user_info(token: str) -> UserInfo | None:
    if not token:
        return None
    ip = request.remote_addr
    forwarded_ip = request.headers.get('X-Forwarded-For')
    if forwarded_ip:
        ip = forwarded_ip.split(',')[0].split()
    params = {
        'appid': GREE_SSO_APP_ID,
        'appkey': GREE_SSO_APP_KEY,
        'ip': ip,
        'token': token
    }
    response = requests.get(GREE_SSO_URL_GET_USER_INFO, params=params)
    if response.status_code == 200:
        json_data = response.json()
        user_info = UserInfo(**json_data)
        logging.exception(json_data)
        user_info.user_id = ''
        if 'Success' in json_data and user_info.Success:
            return user_info
        else:
            raise GreeTokenExpiredError(f"用户信息过期，请重新登录")


# 获取redis——key
def get_redis_key(mail: str) -> str:
    return GREE_REDIS_KEY + mail


# 根据token获取userinfo
def get_gree_token_pair(token: str) -> TokenGree:
    user_info = get_user_info(token)
    account = AccountService.get_user_through_email(user_info.OpenID)
    if not account:
        #  没有账号信息新注册再登录
        email = user_info.OpenID
        name = user_info.UserName
        password = user_info.AppAccount + "@GreeSSO2025"
        language = 'zh-Hans'
        status = models.AccountStatus.ACTIVE
        is_setup = True
        workspace = False
        account = RegisterService.register(email, name, password, None, None, language, status, is_setup, workspace)
        # TenantService.create_owner_tenant_if_not_exist(account=account, is_setup=True)
    redis_key = get_redis_key(user_info.StaffID)
    user_info.user_id = account.id
    redis_client.set(redis_key, json.dumps(user_info.__dict__))
    login_ip = GreeSsoService.get_ip_address()
    if user_info.UserName != account.name:
        account.name = user_info.UserName
    account.last_login_ip = login_ip
    AccountService.update_account(account)
    tenant = TenantService.get_tenant_by_account_id(account.id)
    tenant_name = f"{user_info.UserName}'s Workspace"
    gree_name = 'gree'
    gree_tenant_name = f"{gree_name}'s Workspace"
    gree_workspace = False
    if tenant and tenant_name != tenant.name and tenant.name != gree_tenant_name:
        tenant.name = tenant_name
        TenantService.update_tenant(tenant)
    if tenant:
        gree_workspace = True
    token_pair = AccountService.login(account=account, ip_address=extract_remote_ip(request))
    return TokenGree(access_token=token_pair.access_token, refresh_token=token_pair.refresh_token,
                     csrf_token=token_pair.csrf_token, token=token,
                     mail=user_info.AppAccount, workspace=gree_workspace)


def create_or_update_user_info(token: str) -> UserInfo:
    user_info = get_user_info(token)
    account = AccountService.get_user_through_email(user_info.OpenID)
    if not account:
        #  没有账号信息新注册再登录
        email = user_info.OpenID
        name = user_info.UserName
        password = user_info.AppAccount + "@GreeSSO2025"
        language = 'zh-Hans'
        status = models.AccountStatus.ACTIVE
        is_setup = True
        workspace = False
        account = RegisterService.register(
            email,
            name,
            password,
            None,
            None,
            language,
            status,
            is_setup,
            workspace)
        # TenantService.create_owner_tenant_if_not_exist(account=account, is_setup=True)
    redis_key = get_redis_key(user_info.StaffID)
    user_info.user_id = account.id
    redis_client.set(redis_key, json.dumps(user_info.__dict__))
    login_ip = GreeSsoService.get_ip_address()
    if user_info.UserName != account.name:
        account.name = user_info.UserName
    account.last_login_ip = login_ip
    AccountService.update_account(account)
    return user_info


class GreeSsoService:

    @staticmethod
    def gree_sso(callback: str) -> TokenGree:
        token = get_token(callback)
        return get_gree_token_pair(token.Message)

    @staticmethod
    def gree_sso_mail(callback: str) -> TokenMailGree:
        token = get_token(callback)
        user_info = create_or_update_user_info(token.Message)
        return TokenMailGree(mail=user_info.StaffID, token=token.Message)

    @staticmethod
    def gree_login_by_token(token: str) -> TokenGree:
        return get_gree_token_pair(token)

    @staticmethod
    def get_ip_address() -> str:
        ip = request.remote_addr
        forwarded_ip = request.headers.get('X-Forwarded-For')
        if forwarded_ip:
            ip = forwarded_ip.split(',')[0].split()
        return ip

    # @staticmethod
    # def gree_passport_by_token(token: str, passport: str) -> str:
    #     user_info = get_user_info(token)
    #     account = AccountService.get_user_through_email(user_info.OpenID)
    #     if not account:
    #         #  没有账号信息新注册再登录
    #         email = user_info.OpenID
    #         name = user_info.UserName
    #         password = user_info.AppAccount + "@GreeSSO2025"
    #         language = 'zh-Hans'
    #         status = models.AccountStatus.ACTIVE
    #         is_setup = True
    #         worksapce = False
    #         account = RegisterService.register(email, name, password, None, None, language, status, is_setup, worksapce)
    #         # TenantService.create_owner_tenant_if_not_exist(account=account, is_setup=True)
    #     redis_key = get_redis_key(user_info.StaffID)
    #     user_info.user_id = account.id
    #     redis_client.set(redis_key, json.dumps(user_info.__dict__))
    #     token = TokenPassportService.get_passport_token(user_info.StaffID, passport)
    #     return token

    @staticmethod
    def gree_authcode_get_mail(token: str) -> str:
        user_info = get_user_info(token)
        account = AccountService.get_user_through_email(user_info.OpenID)
        if not account:
            #  没有账号信息新注册再登录
            email = user_info.OpenID
            name = user_info.UserName
            password = user_info.AppAccount + "@GreeSSO2025"
            language = 'zh-Hans'
            status = models.AccountStatus.ACTIVE
            is_setup = True
            workspace = False
            account = RegisterService.register(email, name, password, None, None, language, status, is_setup, workspace)
            # TenantService.create_owner_tenant_if_not_exist(account=account, is_setup=True)
        redis_key = get_redis_key(user_info.StaffID)
        user_info.user_id = account.id
        redis_client.set(redis_key, json.dumps(user_info.__dict__))
        AccountService.login(account)
        return user_info.StaffID

    @staticmethod
    def gree_sso_get_token(callback: str) -> str:
        ip = request.remote_addr
        forwarded_ip = request.headers.get('X-Forwarded-For')
        if forwarded_ip:
            ip = forwarded_ip.split(',')[0].split()
        params = {
            'appid': GREE_SSO_APP_ID,
            'appkey': GREE_SSO_APP_KEY,
            'ip': ip,
            'callback': callback
        }
        # 创建一个 Session 对象
        session = requests.Session()
        # 准备请求
        req = requests.Request('GET', GREE_SSO_URL_GET_USER_INFO, params=params)
        prepped = session.prepare_request(req)
        requestTmp = {
            'url': prepped.url,
            'headers': prepped.headers,
            'path': prepped.path_url,
        }
        response = session.send(prepped)
        # response = requests.get(GREE_SSO_URL_GET_TOKEN, params=params)
        if response.status_code == 200:
            json_data = response.json()
            if 'Success' in json_data or 'Message' in json_data:
                return json_data
        if not response:
            return json.dumps(requestTmp)
        else:
            return response.json()

    @staticmethod
    def gree_sso_sign_out(token: str):
        if not token:
            return
        ip = request.remote_addr
        forwarded_ip = request.headers.get('X-Forwarded-For')
        if forwarded_ip:
            ip = forwarded_ip.split(',')[0].split()
        params = {
            'appid': GREE_SSO_APP_ID,
            'appkey': GREE_SSO_APP_KEY,
            'ip': ip,
            'token': token
        }
        # 创建一个 Session 对象
        session = requests.Session()
        # 准备请求
        req = requests.Request('GET', GREE_SSO_SIGN_OUT, params=params)
        prepped = session.prepare_request(req)
        requestTmp = {
            'url': prepped.url,
            'headers': prepped.headers,
            'path': prepped.path_url,
        }
        response = session.send(prepped)

    @staticmethod
    def gree_sso_get_user_info(token: str) -> str:
        ip = request.remote_addr
        forwarded_ip = request.headers.get('X-Forwarded-For')
        if forwarded_ip:
            ip = forwarded_ip.split(',')[0].split()
        params = {
            'appid': GREE_SSO_APP_ID,
            'appkey': GREE_SSO_APP_KEY,
            'ip': ip,
            'token': token
        }
        # 创建一个 Session 对象
        session = requests.Session()
        # 准备请求
        req = requests.Request('GET', GREE_SSO_URL_GET_USER_INFO, params=params)
        prepped = session.prepare_request(req)
        requestTmp = {
            'url': prepped.url,
            'headers': prepped.headers,
            'path': prepped.path_url,
        }
        response = session.send(prepped)
        if response.status_code == 200:
            json_data = response.json()
            return json_data
        if not response:
            return json.dumps(requestTmp)
        else:
            return response.json()


# 根据条件获取conversation
class GreeAppConversationService:
    @staticmethod
    def get_gree_app_conversations(
        page_number: int,
        page_size: int,
        app_id: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        user_id: str | None = None,
        create_sort: str | None = None,
    ) -> tuple[list, int]:

        query: Query = db.session.query(Conversation)
        filter_conditions = []
        if app_id:
            filter_conditions.append(Conversation.app_id == app_id)
        if start_date:
            filter_conditions.append(Conversation.created_at >= start_date)
        if end_date:
            filter_conditions.append(Conversation.created_at <= end_date)
        if user_id:
            filter_conditions.append(Conversation.from_account_id == user_id)
        # 应用过滤条件
        if filter_conditions:
            query = query.filter(*filter_conditions)
        if create_sort == "asc":
            query = query.order_by(Conversation.created_at.asc())
        if create_sort == "desc":
            query = query.order_by(Conversation.created_at.desc())
        total = query.with_entities(Conversation.id).count() if filter_conditions else query.count()
        page_number = max(page_number, 1)
        page_size = min(page_size, 100)
        offset = (page_number - 1) * page_size
        conversation_models = query.offset(offset).limit(page_size).all()
        conversation_list = []
        for conv in conversation_models:
            # 遍历模型所有字段，转换为字典
            conv_dict = {col.name: getattr(conv, col.name) for col in conv.__table__.columns}

            # 处理datetime类型（JSON无法序列化，转为字符串）
            for key, value in conv_dict.items():
                if isinstance(value, datetime):
                    conv_dict[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                # 处理Decimal类型（若有金额/价格字段需添加）
                elif isinstance(value, Decimal):
                    conv_dict[key] = float(value)
                # 处理空值（统一转为None，避免JSON序列化问题）
                elif value in ("NULL", "", None):
                    conv_dict[key] = None

        conversation_list.append(conv_dict)
        return conversation_list, total


#  根据条件获取message并按照时间线去排列(树状展示)
class GreeAppMessageService:

    @staticmethod
    def get_gree_app_messages(
        page_number: int,
        page_size: int,
        app_id: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        user_id: str | None = None,
        conversation_id: str | None = None,
    ) -> tuple[list, int]:
        query: Query = db.session.query(Message)
        filter_conditions = []
        if app_id:
            filter_conditions.append(Message.app_id == app_id)
        if conversation_id:
            filter_conditions.append(Message.conversation_id == conversation_id)
        if start_date:
            filter_conditions.append(Message.created_at >= start_date)
        if end_date:
            filter_conditions.append(Message.created_at <= end_date)
        if user_id:
            filter_conditions.append(Message.from_account_id == user_id)
        # 应用过滤条件
        if filter_conditions:
            query = query.filter(*filter_conditions)
        # 2. 优化总记录数查询（避免全表扫描）
        total = query.with_entities(func.count(Message.id)).scalar() or 0
        page_number = max(int(page_number), 1)
        page_size = min(int(page_size), 100)  # 限制最大页大小为100
        offset = (page_number - 1) * page_size

        # 4. 查询分页数据并转换为字典
        message_list = query.offset(offset).limit(page_size).all()
        result_list = []
        if message_list:
            for msg in message_list:
                process_msg = {}
                for c in msg.__table__.columns:
                    field_name = c.name
                    field_value = getattr(msg, field_name)

                    # 处理datetime类型：转为字符串
                    if isinstance(field_value, datetime):
                        process_msg[field_name] = field_value.strftime("%Y-%m-%d %H:%M:%S")
                    # 处理空值：统一转为None
                    elif field_value in ("NULL", "", None) or (
                        isinstance(field_value, str) and field_value.strip() == ""):
                        process_msg[field_name] = None
                    # 其他类型直接保留
                    else:
                        process_msg[field_name] = field_value
                parent_id = process_msg.get("parent_message_id")
                if parent_id in ("NULL", "", None) or (isinstance(parent_id, str) and parent_id.strip() == ""):
                    process_msg["parent_message_id"] = None
                else:
                    process_msg["parent_message_id"] = parent_id.strip() if isinstance(parent_id, str) else parent_id
                process_msg["child_message"] = []
                result_list.append(process_msg)
        id_to_msg = {msg["id"]: msg for msg in result_list}
        root_nodes = []
        for msg in result_list:
            parent_id = msg["parent_message_id"]
            if parent_id and parent_id in id_to_msg:
                id_to_msg[parent_id]["child_message"].append(msg)
            else:
                root_nodes.append(msg)

        # 7. 按created_at排序根节点和子节点（按时间正序）
        def sort_by_created_at(msg_list):
            # 按created_at字符串排序（格式统一，可直接比较）
            msg_list.sort(key=lambda x: x["created_at"])
            for msg in msg_list:
                if msg["child_message"]:
                    sort_by_created_at(msg["child_message"])

        sort_by_created_at(root_nodes)

        return root_nodes, total


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            # 将datetime转为字符串（格式：YYYY-MM-DD HH:MM:SS）
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        # 处理其他非序列化类型（如None/Decimal等）
        elif obj is None:
            return None
        elif isinstance(obj, (int, float, str, bool)):
            return obj
        # 其他类型默认处理
        return super().default(obj)
