from app import create_app
from extensions.ext_database import db
from sqlalchemy import text

app = create_app()
with app.app_context():
    # 查询表结构
    result = db.session.execute(text("""
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = 'tools_organization'
        ORDER BY ordinal_position
    """))
    
    print("tools_organization 表结构：")
    print("-" * 80)
    for row in result:
        print(f"  {row.column_name}: {row.data_type} (nullable: {row.is_nullable}, default: {row.column_default})")
    
    # 查询表中的数据
    print("\n表中的数据（前5条）：")
    print("-" * 80)
    data_result = db.session.execute(text("SELECT * FROM tools_organization LIMIT 5"))
    for row in data_result:
        print(f"  {dict(row._mapping)}")