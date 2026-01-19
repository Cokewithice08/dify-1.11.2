from pydantic import BaseModel

import models

from .account_service import AccountService, RegisterService, TenantService


class WorkspaceAdmin(BaseModel):
    mail: str
    parent_mail: str


# 创建账号信息和workspace
def create_workspace(workspace: WorkspaceAdmin):
    if workspace.parent_mail:
        mail = workspace.parent_mail + '@it2004.gree.com.cn'
        account = AccountService.get_user_through_email(mail)
        if not account:
            email = mail
            name = workspace.parent_mail
            password = workspace.parent_mail + "@GreeSSO2025"
            language = 'zh-Hans'
            status = models.AccountStatus.ACTIVE
            is_setup = True
            workspace = True
            account = RegisterService.register(email, name, password, None, None, language, status, is_setup, workspace)
        parent_tenant = TenantService.get_account_owner_tenant_by_account(account)
        if not parent_tenant:
            tenant_name = f"{account.name}'s Workspace"
            tenant_setup = True
            TenantService.create_owner_tenant_if_not_exist(account, tenant_name, tenant_setup)
            parent_tenant = TenantService.get_account_owner_tenant_by_account(account)
        if workspace.mail:
            tenant_mail = workspace.mail + '@it2004.gree.com.cn'
            tenant_account = AccountService.get_user_through_email(tenant_mail)
            if not tenant_account:
                email = tenant_mail
                name = workspace.mail
                password = workspace.mail + "@GreeSSO2025"
                language = 'zh-Hans'
                status = models.AccountStatus.ACTIVE
                is_setup = True
                workspace = True
                tenant_account = RegisterService.register(email, name, password, None, None, language, status, is_setup,
                                                          workspace)
            child_tenant = TenantService.get_account_owner_tenant_by_account(tenant_account)
            if not child_tenant:
                tenant_name = f"{tenant_account.name}'s Workspace"
                tenant_setup = True
                TenantService.create_owner_tenant_if_not_exist(tenant_account, tenant_name, tenant_setup)
                child_tenant = TenantService.get_account_owner_tenant_by_account(tenant_account)
            tenant_account_join = TenantService.create_tenant_member(child_tenant, account, "admin")
            # ProviderModelService.synchronous_provider_model_by_gree_admin(child_tenant.id)


class GreeOrganizationService:

    #  提供给签审的接口：为创建的workspace添加管理员
    @staticmethod
    def create_workspace_admin(param: list[WorkspaceAdmin]):
        if param:
            for workspace_admin in param:
                create_workspace(workspace_admin)
