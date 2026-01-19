import json
import logging

import requests
from flask import request
from pydantic import BaseModel
from libs.helper import extract_remote_ip
import models
from extensions.ext_redis import redis_client

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
def get_user_info(token: str) -> UserInfo:
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
        user_info.user_id = ''
        return user_info


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
    token_pair = AccountService.login(account=account,ip_address=extract_remote_ip(request))
    return TokenGree(access_token=token_pair.access_token, refresh_token=token_pair.refresh_token, csrf_token=token_pair.csrf_token, token=token,
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

