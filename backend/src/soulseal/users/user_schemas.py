"""
用户模块数据模型

定义用户相关的核心数据模型,包括用户角色和用户基础信息。
"""

from pydantic import BaseModel, Field, EmailStr, field_validator, constr, ConfigDict, model_validator, model_serializer
from argon2 import PasswordHasher
from typing import Optional, Dict, Any, List, Set, Union, Generic, TypeVar
from datetime import datetime, timedelta
from string import ascii_letters, digits
from enum import Enum

import re
import uuid
import secrets

import logging

logger = logging.getLogger(__name__)

class UserRole(str, Enum):
    """用户角色枚举"""
    @classmethod
    def has_role(cls, need_role: "UserRole", have_roles: Set["UserRole"]) -> bool:
        """检查用户是否具有指定角色(包含继承的角色)"""
        return need_role in cls.get_role_hierarchy(have_roles)

    @classmethod
    def get_role_hierarchy(cls, user_roles: Set["UserRole"] = None) -> Set["UserRole"]:
        """获取角色层级关系"""
        hierarchy = {
            cls.ADMIN: {cls.ADMIN, cls.OPERATOR, cls.USER, cls.GUEST},
            cls.OPERATOR: {cls.OPERATOR, cls.USER, cls.GUEST},
            cls.USER: {cls.USER, cls.GUEST},
            cls.GUEST: {cls.GUEST}
        }

        roles_hierarchy = set()
        for role in user_roles:
            roles_hierarchy.update(hierarchy.get(role, {cls.GUEST}))

        return roles_hierarchy

    ADMIN = "admin"          # 管理员
    OPERATOR = "operator"    # 运营人员
    USER = "user"           # 普通用户
    GUEST = "guest"         # 访客

class User(BaseModel):
    """用户基础信息模型"""
    @classmethod
    def can_update_field(cls, fields: List[str]) -> bool:
        """检查是否可以更新字段"""
        allowed_fields = ["username", "email", "mobile", "display_name", "bio"]
        return all(field in allowed_fields for field in fields)

    @staticmethod
    def generate_random_password(length: int = 12) -> str:
        """生成随机密码"""
        alphabet = ascii_letters + digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length-2))
        password += secrets.choice(digits)
        password += secrets.choice("!@#$%^&*")
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    @classmethod
    def hash_password(cls, password: str) -> str:
        """密码加密"""
        ph = PasswordHasher()
        return ph.hash(password)

    model_config = ConfigDict(
        from_attributes=True,
        validate_assignment=True
    )

    # 用户必要信息
    username: constr(min_length=3, max_length=32) = Field(..., description="用户名")
    password_hash: str = Field(default="", description="密码哈希值")

    # 用户ID
    user_id: str = Field(
        default_factory=lambda: f"u-{str(uuid.uuid4().hex)[:8]}",
        description="用户唯一标识"
    )

    # 用户联系方式
    email: Union[EmailStr, None, str] = Field(default=None, description="电子邮箱")
    email_verified: bool = Field(default=False, description="邮箱是否验证")
    mobile: Union[str, None] = Field(default=None, description="手机号")
    mobile_verified: bool = Field(default=False, description="手机号是否验证")

    # 用户个人资料
    display_name: str = Field(default="", description="显示名称")
    bio: str = Field(default="", description="个人简介")

    # 用户角色
    roles: Set[UserRole] = Field(
        default_factory=lambda: {UserRole.USER},
        description="用户角色集合"
    )

    # 用户状态
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    require_password_change: bool = Field(default=False, description="是否需要修改密码")
    last_password_change: datetime = Field(default_factory=datetime.now, description="最后密码修改时间")
    password_expires_days: float = Field(default=90.0, description="密码有效期(天)")
    last_login: Optional[datetime] = Field(default=None, description="最后登录时间")
    failed_login_attempts: int = Field(default=0, description="登录失败次数")
    last_failed_login: Optional[datetime] = Field(default=None, description="最后失败登录时间")
    is_locked: bool = Field(default=False, description="是否锁定")
    is_active: bool = Field(default=True, description="是否激活")

    @model_validator(mode='after')
    def ensure_profile_fields(self) -> 'User':
        """确保个人资料字段存在
        
        即使在历史数据中，也确保display_name和bio字段总是存在。
        """
        if not hasattr(self, 'display_name') or self.display_name is None:
            self.display_name = self.username
        
        if not hasattr(self, 'bio') or self.bio is None:
            self.bio = ""
        
        return self

    @field_validator('username')
    def validate_username(cls, v: str) -> str:
        """验证用户名格式"""
        if not v[0].isalpha():
            raise ValueError("用户名必须以字母开头")
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', v):
            raise ValueError("用户名只能包含字母、数字和下划线")
        return v

    @field_validator('roles', mode='before')
    def validate_roles(cls, v: Union[str, UserRole]) -> UserRole:
        """验证并转换角色值"""
        if isinstance(v, str):
            return UserRole(v)
        return v

    def verify_password(self, to_verify_password: str) -> Dict[str, bool]:
        """密码验证
        
        如果密码正确，返回一个包含rehash标志的字典
        如果密码错误，抛出异常
        
        Args:
            to_verify_password: 待验证的密码
            
        Returns:
            Dict[str, bool]: 包含rehash标志的字典
            
        Raises:
            Exception: 当密码不匹配时抛出
        """
        if not to_verify_password:
            raise Exception("密码不能为空")
        
        ph = PasswordHasher()
        try:
            ph.verify(self.password_hash, to_verify_password)
            
            # 检查是否需要重新哈希
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(to_verify_password)
                return {"rehash": True}
            return {"rehash": False}
        except Exception as e:
            raise Exception(f"密码错误: {str(e)}")
    
    def is_password_expired(self) -> bool:
        """检查密码是否过期

        使用 password_expires_days 设置密码过期时间，可以强制要求用户定期修改密码。
        """
        if not self.last_password_change:
            return True
        expiry_date = self.last_password_change + timedelta(days=self.password_expires_days)
        return datetime.now() >= expiry_date

    def record_login_attempt(self, success: bool) -> None:
        """记录登录尝试"""
        current_time = datetime.now()
        if success:
            self.failed_login_attempts = 0
            self.last_login = current_time
            self.last_failed_login = None
            self.is_locked = False
        else:
            self.failed_login_attempts += 1
            self.last_failed_login = current_time
            if self.failed_login_attempts >= 5:
                self.is_locked = True
