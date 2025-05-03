'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { useApiBase } from '@/hooks/useApiBase';

interface AuthContextType {
    token: string | null;
    user: any | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (username: string, password: string) => Promise<void>;
    logout: () => void;
    setToken: (token: string | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
    const { API_BASE_URL } = useApiBase();
    const [token, setTokenState] = useState<string | null>(null);
    const [user, setUser] = useState<any | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const router = useRouter();

    const setToken = (newToken: string | null) => {
        setTokenState(newToken);
        if (newToken) {
            localStorage.setItem('auth_token', newToken);
        } else {
            localStorage.removeItem('auth_token');
        }
    };

    // 在客户端初始化时从localStorage加载令牌
    useEffect(() => {
        const storedToken = localStorage.getItem('auth_token');
        if (storedToken) {
            setTokenState(storedToken);
            fetchUserInfo(storedToken);
        } else {
            setIsLoading(false);
        }
    }, []);

    // 获取用户信息
    const fetchUserInfo = async (currentToken: string) => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/profile`, {
                headers: {
                    'Authorization': `Bearer ${currentToken}`
                },
                credentials: 'include'
            });

            if (response.ok) {
                const userData = await response.json();
                setUser(userData);
            } else {
                // 如果获取用户信息失败，清除令牌
                setToken(null);
            }
        } catch (error) {
            console.error('获取用户信息失败:', error);
            setToken(null);
        } finally {
            setIsLoading(false);
        }
    };

    // 登录函数
    const login = async (username: string, password: string) => {
        setIsLoading(true);
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || '登录失败');
            }

            const data = await response.json();
            const authHeader = response.headers.get('Authorization');

            if (authHeader?.startsWith('Bearer ')) {
                const accessToken = authHeader.substring(7);
                setToken(accessToken);
                setUser(data.user);
                router.push('/dashboard'); // 登录成功后跳转到仪表板
            } else {
                throw new Error('未收到有效的认证令牌');
            }
        } catch (error: any) {
            console.error('登录失败:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

    // 登出函数
    const logout = async () => {
        try {
            await fetch(`${API_BASE_URL}/api/auth/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                credentials: 'include'
            });
        } catch (error) {
            console.error('登出请求失败:', error);
        } finally {
            setToken(null);
            setUser(null);
            router.push('/login');
        }
    };

    const value = {
        token,
        user,
        isAuthenticated: !!token,
        isLoading,
        login,
        logout,
        setToken
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
} 