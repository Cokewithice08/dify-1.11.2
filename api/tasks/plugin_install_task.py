"""
插件安装异步任务
"""
import logging

from celery import shared_task

from configs import dify_config
from extensions.ext_database import db
from services.plugin.plugin_service import PluginService

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def install_plugins_for_tenant_task(self, tenant_id: str):
    """
    异步为租户安装插件

    Args:
        tenant_id: 租户ID
    """
    try:
        logger.info(f"Starting plugin installation for tenant: {tenant_id}")

        # 调用同步方法安装插件
        PluginService.add_plugin_to_user(tenant_id)

        logger.info(f"Plugin installation completed for tenant: {tenant_id}")

    except Exception as e:
        logger.exception(f"Failed to install plugins for tenant {tenant_id}: {str(e)}")
        # 重试任务
        raise self.retry(exc=e, countdown=60)
