from datetime import datetime

from .engine import db

class GreeOrganization(db.Model):
    __tablename__ = 'gree_organization'
    
    id = db.Column(db.String(255), primary_key=True)
    company = db.Column(db.String(128), nullable=False)
    dept = db.Column(db.String(128), nullable=False)
    org_id = db.Column(db.String(36), nullable=False)
    parent_org = db.Column(db.String(36), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'org_id': self.org_id,
            'parent_org_id': self.parent_org,
            'org_name': self.dept if self.dept else self.company,  # 优先使用dept，如果为空则使用company
            'level': 1 if not self.parent_org or self.parent_org == '-1' else 2  # 根节点判断
        }

