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
    };

    useEffect(() => {
        const refreshAccessToken = async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/auth/refresh-token`, {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' },
                    credentials: 'include'
                });
                if (!response.ok) {
                    throw new Error('刷新令牌失败');
                }
                const data = await response.json();
                setTokenState(data.access_token);
                setUser(data.user);
            } catch (error) {
                console.error('刷新令牌失败:', error);
            } finally {
                setIsLoading(false);
            }
        };
        refreshAccessToken();
    }, []);

    const login = async (username: string, password: string) => {
        setIsLoading(true);
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || '登录失败');
            }
            const data = await response.json();
            const accessToken = data.access_token;
            setToken(accessToken);
            setUser(data.user);
            router.push('/dashboard');
        } catch (error: any) {
            console.error('登录失败:', error);
            throw error;
        } finally {
            setIsLoading(false);
        }
    };

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