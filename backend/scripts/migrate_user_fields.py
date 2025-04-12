#!/usr/bin/env python
"""
数据库迁移脚本：添加缺失的用户字段

此脚本为所有现有用户添加默认的display_name和bio字段，
解决历史数据问题。
"""

import os
import sys
import logging
from pathlib import Path

# 确保可以导入soulseal模块
script_dir = Path(__file__).resolve().parent
backend_dir = script_dir.parent
sys.path.insert(0, str(backend_dir))

from soulseal.users import UsersManager
from voidring import IndexedRocksDB

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_user_fields(data_dir: str):
    """迁移用户字段
    
    为所有现有用户添加缺失的display_name和bio字段。
    
    Args:
        data_dir: 数据库目录
    """
    logger.info(f"开始迁移用户字段，数据库位置: {data_dir}")
    
    # 初始化数据库和用户管理器
    db = IndexedRocksDB(data_dir)
    users_manager = UsersManager(db)
    
    # 获取所有用户
    all_users = users_manager.list_users()
    logger.info(f"共发现 {len(all_users)} 个用户")
    
    # 记录更新计数
    update_count = 0
    error_count = 0
    
    # 遍历所有用户
    for user in all_users:
        user_id = user.user_id
        username = user.username
        
        # 检查display_name和bio字段是否需要初始化
        needs_update = False
        update_fields = {}
        
        # 检查display_name
        if not hasattr(user, 'display_name') or user.display_name is None:
            update_fields['display_name'] = username
            needs_update = True
            logger.info(f"用户 {username} ({user_id}) 缺少display_name字段")
        
        # 检查bio
        if not hasattr(user, 'bio') or user.bio is None:
            update_fields['bio'] = ""
            needs_update = True
            logger.info(f"用户 {username} ({user_id}) 缺少bio字段")
        
        # 更新用户
        if needs_update:
            try:
                result = users_manager.update_user(user_id, **update_fields)
                if result.is_ok():
                    update_count += 1
                    logger.info(f"已更新用户 {username} ({user_id})")
                else:
                    error_count += 1
                    logger.error(f"更新用户 {username} ({user_id}) 失败: {result.error}")
            except Exception as e:
                error_count += 1
                logger.error(f"更新用户 {username} ({user_id}) 时出错: {str(e)}")
    
    # 关闭数据库
    db.close()
    
    # 输出迁移结果
    logger.info(f"迁移完成: 成功 {update_count} 个, 失败 {error_count} 个")

if __name__ == "__main__":
    # 从命令行参数或环境变量获取数据库路径
    data_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SOULSEAL_DATA_DIR")
    
    if not data_dir:
        logger.error("请指定数据库目录路径 (SOULSEAL_DATA_DIR 环境变量或命令行参数)")
        sys.exit(1)
    
    migrate_user_fields(data_dir) 