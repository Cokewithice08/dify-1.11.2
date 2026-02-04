from models import Account, TenantAccountJoin
from models.engine import db


class GreeTenantAccountService:

    @staticmethod
    def get_current_tenant_id(user: Account) -> str | None:
        if user:
            tenant_account_id = str(
                db.session.query(TenantAccountJoin.tenant_id)
                .filter_by(account_id=user.id, role='owner')
                .scalar() or ""
            )
            return tenant_account_id
