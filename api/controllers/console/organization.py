from flask import Blueprint, jsonify, request
from models import GreeOrganization
from libs.login import login_required
from extensions.ext_redis import redis_client
import json
import logging

logger = logging.getLogger(__name__)

organization_bp = Blueprint('organization', __name__)

@organization_bp.route('/organizations', methods=['GET'])
def get_organizations():
    """
    获取组织架构树
    """
    try:
        # 使用organizations前缀的Redis key
        cache_key = 'organizations:tree'
        
        # 尝试从Redis缓存中获取数据
        cached_data = redis_client.get(cache_key)
        if cached_data:
            logger.info(f'从Redis缓存中获取组织架构数据，key: {cache_key}')
            return jsonify({
                'success': True,
                'data': json.loads(cached_data),
                'message': '获取组织架构成功',
                'source': 'cache'
            })
        
        # 从数据库查询数据
        logger.info('从数据库查询组织架构数据')
        organizations = GreeOrganization.query.all()
        logger.info(f'查询到 {len(organizations)} 条组织架构记录')
        
        # 构建树形结构
        organization_dict = {org.org_id: org.to_dict() for org in organizations}
        logger.info(f'构建组织字典，包含 {len(organization_dict)} 个节点')
        
        tree_data = build_organization_tree(organization_dict)
        logger.info(f'构建组织树，包含 {len(tree_data)} 个根节点')
        
        # 存储到Redis缓存，永不过期（组织架构数据基本不变动）
        redis_client.set(cache_key, json.dumps(tree_data))
        logger.info(f'组织架构数据已存入Redis缓存，key: {cache_key}（永不过期）')
        
        return jsonify({
            'success': True,
            'data': tree_data,
            'message': '获取组织架构成功',
            'source': 'database'
        })
    except Exception as e:
        logger.error(f'获取组织架构失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': '获取组织架构失败'
        })

@organization_bp.route('/organizations/selected', methods=['POST'])
def get_selected_organizations():
    """
    获取选择的组织架构对应的三级org_id
    """
    try:
        data = request.get_json()
        selected_org_id = data.get('org_id')
        
        if not selected_org_id:
            return jsonify({
                'success': False,
                'message': '请提供org_id'
            })
        
        # 使用相同的缓存key
        cache_key = 'organizations:tree'
        
        # 尝试从Redis缓存中获取数据
        cached_data = redis_client.get(cache_key)
        if not cached_data:
            # 从数据库查询数据
            organizations = GreeOrganization.query.all()
            organization_dict = {org.org_id: org.to_dict() for org in organizations}
            tree_data = build_organization_tree(organization_dict)
            redis_client.set(cache_key, json.dumps(tree_data))
        else:
            tree_data = json.loads(cached_data)
        
        # 获取选择的组织节点
        selected_node = find_node_by_org_id(tree_data, selected_org_id)
        if not selected_node:
            return jsonify({
                'success': False,
                'message': '未找到指定的组织'
            })
        
        # 提取所有三级org_id
        third_level_org_ids = extract_third_level_org_ids(selected_node)
        
        # 打印结果
        logger.info(f'选择的组织ID: {selected_org_id}')
        logger.info(f'提取的三级org_id: {third_level_org_ids}')
        
        return jsonify({
            'success': True,
            'data': {
                'org_id': selected_org_id,
                'third_level_org_ids': third_level_org_ids
            },
            'message': '获取选择的组织架构成功'
        })
    except Exception as e:
        logger.error(f'获取选择的组织架构失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': '获取选择的组织架构失败'
        })

def build_organization_tree(organization_dict):
    """
    构建组织架构树形结构
    """
    tree = []
    # 首先构建所有节点
    nodes = {org_id: {'id': org_id, 'name': data['org_name'], 'children': []} 
             for org_id, data in organization_dict.items()}
    
    # 构建父子关系
    for org_id, data in organization_dict.items():
        parent_org_id = data['parent_org_id']
        if not parent_org_id or parent_org_id == '-1':
            # 根节点
            tree.append(nodes[org_id])
        else:
            # 子节点
            if parent_org_id in nodes:
                nodes[parent_org_id]['children'].append(nodes[org_id])
    
    return tree

def find_node_by_org_id(nodes, org_id):
    """
    根据org_id查找节点
    """
    for node in nodes:
        if node['id'] == org_id:
            return node
        if node.get('children'):
            found = find_node_by_org_id(node['children'], org_id)
            if found:
                return found
    return None

@organization_bp.route('/cache/clear', methods=['POST'])
def clear_organization_cache():
    """
    清除组织架构缓存
    """
    try:
        cache_key = 'organizations:tree'
        redis_client.delete(cache_key)
        logger.info(f'已清除组织架构缓存，key: {cache_key}')
        
        return jsonify({
            'success': True,
            'message': '缓存清除成功'
        })
    except Exception as e:
        logger.error(f'清除缓存失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': '清除缓存失败'
        })

def extract_third_level_org_ids(current_node, level=1):
    """
    提取第三级组织的org_id
    """
    third_level_ids = []
    
    def traverse(current_node, level=1):
        if level == 3:
            third_level_ids.append(current_node['id'])
        elif level < 3 and current_node.get('children'):
            for child in current_node['children']:
                traverse(child, level + 1)
    
    traverse(current_node, level)
    return third_level_ids

# 注册蓝图
from . import bp

bp.register_blueprint(organization_bp, url_prefix='/organizations')
