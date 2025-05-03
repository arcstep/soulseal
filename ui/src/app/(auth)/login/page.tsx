'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/context/AuthContext';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
    const { login, isAuthenticated } = useAuth();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const router = useRouter();

    // 如果用户已登录，重定向到仪表板
    useEffect(() => {
        if (isAuthenticated) {
            router.push('/dashboard');
        }
    }, [isAuthenticated, router]);

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            await login(username, password);
            // 登录成功，将在AuthContext中处理跳转
        } catch (err: any) {
            console.error("登录失败:", err);
            if (err.response && err.response.data && err.response.data.detail) {
                setError(err.response.data.detail);
            } else if (err.message) {
                setError(err.message);
            } else {
                setError('登录失败，请稍后再试');
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background">
            <div className="bg-card text-card-foreground p-8 rounded-lg shadow-md w-full max-w-md">
                <h1 className="text-3xl font-bold mb-6 text-center">欢迎回来</h1>
                <form onSubmit={handleSubmit}>
                    <div className="mb-4">
                        <label htmlFor="username" className="block text-muted-foreground mb-2">
                            用户名
                        </label>
                        <input
                            type="text"
                            id="username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            className="w-full border border-input bg-background text-foreground rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary"
                            placeholder="输入您的用户名"
                        />
                    </div>
                    <div className="mb-6">
                        <label htmlFor="password" className="block text-muted-foreground mb-2">
                            密码
                        </label>
                        <input
                            type="password"
                            id="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="w-full border border-input bg-background text-foreground rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary"
                            placeholder="输入您的密码"
                        />
                    </div>
                    {error && <p className="text-destructive mb-4">{error}</p>}
                    <button
                        type="submit"
                        disabled={loading}
                        className={`w-full bg-primary text-primary-foreground px-4 py-2 rounded-md hover:bg-primary/90 transition-colors duration-300 ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
                    >
                        {loading ? '登录中...' : '登录'}
                    </button>
                </form>
            </div>
        </div>
    );
} 