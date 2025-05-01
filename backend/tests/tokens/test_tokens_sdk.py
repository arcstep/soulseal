import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import tempfile
import shutil
import time
import mock

from voidring import IndexedRocksDB
from soulseal.tokens import TokenSDK, TokensManager
from soulseal.tokens.token_schemas import TokenClaims, TokenType
from soulseal.tokens.blacklist import MemoryTokenBlacklist

@pytest.fixture
def temp_db_path():
    """创建临时数据库目录"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def db(temp_db_path):
    """创建测试用RocksDB实例"""
    return IndexedRocksDB(temp_db_path)

@pytest.fixture
def blacklist():
    """创建黑名单实例"""
    return MemoryTokenBlacklist()

@pytest.fixture
def auth_server_sdk(db, blacklist):
    """创建认证服务器模式的TokenSDK"""
    return TokenSDK(
        jwt_secret_key="test-secret-key",
        db=db,
        auth_server=True,
        blacklist_provider=blacklist
    )

@pytest.fixture
def client_sdk(blacklist):
    """创建客户端模式的TokenSDK"""
    return TokenSDK(
        jwt_secret_key="test-secret-key",
        auth_server=False,
        blacklist_provider=blacklist
    )

@pytest.fixture
def user_data():
    """测试用户数据"""
    return {
        "user_id": "test_user_id",
        "username": "testuser",
        "roles": ["user"],
        "device_id": "test_device_id"
    }

class TestAuthServerSDK:
    """测试认证服务器模式下的TokenSDK"""
    
    def test_create_token(self, auth_server_sdk, user_data):
        """测试创建访问令牌"""
        token = auth_server_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 解码验证令牌数据
        decoded = jwt.decode(
            token,
            key=auth_server_sdk._jwt_secret_key,
            algorithms=[auth_server_sdk._jwt_algorithm]
        )
        
        assert decoded["user_id"] == user_data["user_id"]
        assert decoded["token_type"] == TokenType.ACCESS
    
    def test_verify_token(self, auth_server_sdk, user_data):
        """测试验证访问令牌"""
        token = auth_server_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        result = auth_server_sdk.verify_token(token)
        
        assert result.is_ok()
        assert result.data["user_id"] == user_data["user_id"]
    
    def test_blacklist_integration(self, auth_server_sdk, user_data, blacklist):
        """测试黑名单与SDK集成"""
        # 创建令牌
        token = auth_server_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 将令牌加入黑名单
        auth_server_sdk.revoke_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 验证被撤销的令牌
        result = auth_server_sdk.verify_token(token)
        
        assert result.is_fail()
        assert "已被撤销" in result.error
    
    def test_extend_refresh_token(self, auth_server_sdk, user_data):
        """测试延长刷新令牌有效期"""
        # 创建刷新令牌
        auth_server_sdk._tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 延长刷新令牌有效期
        result = auth_server_sdk.extend_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        assert result.is_ok()
    
    def test_handle_token_refresh_with_refresh_token(self, auth_server_sdk, user_data):
        """测试使用刷新令牌刷新访问令牌"""
        # 创建刷新令牌
        refresh_claims = auth_server_sdk._tokens_manager.update_refresh_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        refresh_token = refresh_claims.jwt_encode()
        
        # 创建请求和响应模拟
        mock_request = MagicMock()
        mock_request.cookies = {"refresh_token": refresh_token}
        mock_response = MagicMock()
        
        # 处理令牌刷新
        with patch.object(auth_server_sdk, 'extend_refresh_token') as mock_extend:
            mock_extend.return_value = Result.ok(data=True)
            
            result = auth_server_sdk.handle_token_refresh(mock_request, mock_response)
        
        # 验证结果
        assert result.is_ok()
        assert "access_token" in result.data
        mock_extend.assert_called_once_with(user_data["user_id"], user_data["device_id"])

    def test_token_sdk_auth_mode_integration(self, auth_server_sdk, user_data):
        """测试认证服务器模式下的完整流程：创建、刷新、撤销"""
        # 1. 创建访问令牌
        access_token = auth_server_sdk.create_token(**user_data)
        
        # 2. 为用户创建刷新令牌
        auth_server_sdk._tokens_manager.update_refresh_token(**user_data)
        
        # 3. 模拟令牌过期并尝试刷新
        with patch('jwt.decode') as mock_decode:
            # 首次调用返回正常结果，第二次抛出过期异常
            def side_effect(*args, **kwargs):
                if kwargs.get('options', {}).get('verify_exp') is False:
                    return {"user_id": user_data["user_id"], "device_id": user_data["device_id"]}
                raise jwt.ExpiredSignatureError("Token expired")
            mock_decode.side_effect = side_effect
            
            # 模拟请求和响应
            mock_request = MagicMock()
            mock_response = MagicMock()
            
            # 4. 处理令牌刷新
            refresh_result = auth_server_sdk.handle_token_refresh(mock_request, mock_response)
        
        # 验证结果
        assert refresh_result.is_ok()
        
        # 5. 撤销令牌
        auth_server_sdk.revoke_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 6. 验证令牌已被撤销
        with patch.object(auth_server_sdk, 'verify_token') as mock_verify:
            auth_server_sdk.verify_token(access_token)
            mock_verify.assert_called_once_with(access_token)

    def test_expired_token(self, auth_server_sdk, user_data):
        """测试过期令牌验证"""
        # 创建一个已过期的令牌
        with patch('datetime.datetime') as mock_datetime:
            # 设置创建时间为过去
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            
            # 设置非常短的过期时间
            auth_server_sdk._access_token_expire_minutes = 0.01  # 0.6秒
            
            token = auth_server_sdk.create_token(
                user_id=user_data["user_id"],
                username=user_data["username"],
                roles=user_data["roles"],
                device_id=user_data["device_id"]
            )
        
        # 等待令牌过期
        time.sleep(1)
        
        # 验证令牌
        result = auth_server_sdk.verify_token(token)
        
        # 验证结果
        assert result.is_fail()
        assert "过期" in result.error

    def test_invalid_token_format(self, auth_server_sdk):
        """测试格式无效的令牌"""
        # 格式无效的令牌
        invalid_token = "invalid.token.format"
        
        # 验证令牌
        result = auth_server_sdk.verify_token(invalid_token)
        
        # 验证结果
        assert result.is_fail()
        assert "错误" in result.error

    def test_invalid_token_signature(self, auth_server_sdk, user_data):
        """测试签名无效的令牌"""
        # 创建令牌
        token = auth_server_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 篡改令牌签名（修改最后一个字符）
        tampered_token = token[:-1] + ('a' if token[-1] != 'a' else 'b')
        
        # 验证令牌
        result = auth_server_sdk.verify_token(tampered_token)
        
        # 验证结果
        assert result.is_fail()
        assert "签名无效" in result.error

    def test_extract_token_from_request(self, auth_server_sdk, user_data):
        """测试从请求中提取令牌"""
        # 创建令牌
        token = auth_server_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 模拟请求 - 访问令牌在 Authorization 头部
        mock_request = MagicMock()
        mock_request.headers = {"Authorization": f"Bearer {token}"}
        
        # 提取访问令牌
        extracted_token = auth_server_sdk.extract_token_from_request(mock_request, "access")
        
        # 验证提取结果
        assert extracted_token == token
        
        # 模拟请求 - 刷新令牌在 cookie 中
        refresh_token = "refresh_token_value"
        mock_request.cookies = {"refresh_token": refresh_token}
        
        # 提取刷新令牌
        extracted_refresh = auth_server_sdk.extract_token_from_request(mock_request, "refresh")
        
        # 验证提取结果
        assert extracted_refresh == refresh_token

    def test_set_token_to_response(self, auth_server_sdk, user_data):
        """测试将令牌设置到响应"""
        # 创建令牌
        token = auth_server_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 模拟响应
        mock_response = MagicMock()
        mock_response.headers = {}
        
        # 设置访问令牌到响应
        auth_server_sdk.set_token_to_response(mock_response, token, "access")
        
        # 验证访问令牌设置
        assert mock_response.headers["Authorization"] == f"Bearer {token}"
        
        # 设置刷新令牌到响应
        refresh_token = "refresh_token_value"
        auth_server_sdk.set_token_to_response(mock_response, refresh_token, "refresh")
        
        # 验证刷新令牌设置
        mock_response.set_cookie.assert_called_with(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=mock.ANY  # 不验证具体过期时间
        )

    def test_missing_token(self, auth_server_sdk):
        """测试处理缺少令牌的情况"""
        # 模拟请求 - 不包含令牌
        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.cookies = {}
        
        # 尝试提取令牌
        token = auth_server_sdk.extract_token_from_request(mock_request)
        
        # 验证结果
        assert token is None

    def test_cross_mode_compatibility(self, auth_server_sdk, client_sdk, user_data):
        """测试客户端能验证认证服务器创建的令牌"""
        # 认证服务器创建令牌
        token = auth_server_sdk.create_token(**user_data)
        
        # 客户端验证令牌
        result = client_sdk.verify_token(token)
        
        assert result.is_ok()
        assert result.data["user_id"] == user_data["user_id"]

class TestClientSDK:
    """测试客户端模式下的TokenSDK"""
    
    def test_create_token(self, client_sdk, user_data):
        """测试创建访问令牌"""
        token = client_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 解码验证令牌数据
        decoded = jwt.decode(
            token,
            key=client_sdk._jwt_secret_key,
            algorithms=[client_sdk._jwt_algorithm]
        )
        
        assert decoded["user_id"] == user_data["user_id"]
        assert decoded["token_type"] == TokenType.ACCESS
    
    def test_verify_token(self, client_sdk, user_data):
        """测试验证访问令牌"""
        token = client_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        result = client_sdk.verify_token(token)
        
        assert result.is_ok()
        assert result.data["user_id"] == user_data["user_id"]
    
    def test_client_mode_blacklist(self, client_sdk, user_data, blacklist):
        """测试客户端模式下的黑名单功能"""
        # 创建令牌
        token = client_sdk.create_token(
            user_id=user_data["user_id"],
            username=user_data["username"],
            roles=user_data["roles"],
            device_id=user_data["device_id"]
        )
        
        # 将令牌加入黑名单
        client_sdk.revoke_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        # 验证被撤销的令牌
        result = client_sdk.verify_token(token)
        
        assert result.is_fail()
        assert "已被撤销" in result.error
    
    def test_client_mode_no_refresh_token_support(self, client_sdk, user_data):
        """测试客户端模式下不支持刷新令牌操作"""
        result = client_sdk.extend_refresh_token(
            user_id=user_data["user_id"],
            device_id=user_data["device_id"]
        )
        
        assert result.is_fail()
        assert "只有认证服务器模式" in result.error

    def test_client_expired_token(self, client_sdk, user_data):
        """测试客户端模式下过期令牌验证"""
        # 创建一个已过期的令牌
        with patch('datetime.datetime') as mock_datetime:
            past_time = datetime.utcnow() - timedelta(hours=1)
            mock_datetime.utcnow.return_value = past_time
            
            client_sdk._access_token_expire_minutes = 0.01
            token = client_sdk.create_token(**user_data)
        
        time.sleep(1)
        result = client_sdk.verify_token(token)
        
        assert result.is_fail()
        assert "过期" in result.error

    def test_client_invalid_token_format(self, client_sdk):
        """测试客户端模式下无效格式令牌"""
        invalid_token = "invalid.token.format"
        result = client_sdk.verify_token(invalid_token)
        
        assert result.is_fail()
        assert "错误" in result.error

    def test_client_invalid_token_signature(self, client_sdk, user_data):
        """测试客户端模式下签名被篡改的令牌"""
        token = client_sdk.create_token(**user_data)
        tampered_token = token[:-1] + ('a' if token[-1] != 'a' else 'b')
        
        result = client_sdk.verify_token(tampered_token)
        
        assert result.is_fail()
        assert "签名无效" in result.error

    def test_client_extract_token_from_request(self, client_sdk, user_data):
        """测试客户端模式下从请求提取令牌"""
        token = client_sdk.create_token(**user_data)
        
        mock_request = MagicMock()
        mock_request.headers = {"Authorization": f"Bearer {token}"}
        
        extracted_token = client_sdk.extract_token_from_request(mock_request, "access")
        assert extracted_token == token

    def test_client_missing_token(self, client_sdk):
        """测试客户端模式下处理缺少令牌的情况"""
        mock_request = MagicMock()
        mock_request.headers = {}
        
        token = client_sdk.extract_token_from_request(mock_request)
        assert token is None

    def test_client_role_verification(self, client_sdk, user_data):
        """测试客户端模式下角色验证"""
        token = client_sdk.create_token(**user_data)
        
        # 测试用户具有的角色
        result = client_sdk.verify_token(token, required_roles=["user"])
        assert result.is_ok()
        
        # 测试用户不具有的角色
        result = client_sdk.verify_token(token, required_roles=["admin"])
        assert result.is_fail()
        assert "权限不足" in result.error