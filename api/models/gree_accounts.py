"""Gree Accounts Model"""
from datetime import datetime
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from .engine import db
from .types import StringUUID


class GreeAccounts(db.Model):
    """Gree SSO账户信息表"""

    __tablename__ = "gree_accounts"
    __table_args__ = (
        sa.PrimaryKeyConstraint("id", name="gree_accounts_pkey"),
    )

    id: Mapped[str] = mapped_column(
        StringUUID,
        server_default=sa.text('gen_random_uuid()'),
        primary_key=True
    )

    # 用户标识字段
    user_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    open_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True, unique=True)
    app_account: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    staff_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    emp_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    hr_emp_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    # 组织架构字段
    org_l1_alias: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    org_l1_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    org_l2_alias: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    org_l2_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    org_l3_alias: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    org_l3_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    # 职位和部门信息
    job: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    department_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    department_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    company_id: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    company_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    title: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    office: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    # 联系信息
    user_name: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    # 领导和状态
    office_leader: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    dept_leader: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)
    in_service: Mapped[bool | None] = mapped_column(sa.Boolean, nullable=True)

    # 认证信息
    token: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(sa.String(255), nullable=True)

    # 时间戳
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime,
        nullable=False,
        server_default=sa.func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime,
        nullable=False,
        server_default=sa.func.current_timestamp(),
        onupdate=sa.func.current_timestamp()
    )
