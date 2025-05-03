'use client';

import { useAuth } from '@/context/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import ThemeSwitch from '@/components/ThemeSwitch';

export default function DashboardPage() {
    const { user, isAuthenticated, isLoading, logout } = useAuth();
    const router = useRouter();

    useEffect(() => {
        // 如果用户未登录且加载完成，重定向到登录页面
        if (!isLoading && !isAuthenticated) {
            router.push('/login');
        }
    }, [isLoading, isAuthenticated, router]);

    // 显示加载状态
    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <p className="text-xl">加载中...</p>
            </div>
        );
    }

    // 如果未认证，显示空白页面 (会被useEffect重定向)
    if (!isAuthenticated) {
        return null;
    }

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-8">
            <div className="max-w-4xl mx-auto bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
                <div className="flex justify-between items-center mb-6">
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">欢迎来到仪表板</h1>
                    <div className="flex items-center space-x-4">
                        <ThemeSwitch />
                        <button
                            onClick={logout}
                            className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded transition-colors duration-300"
                        >
                            登出
                        </button>
                    </div>
                </div>

                <div className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4 mb-6">
                    <h2 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">用户信息</h2>
                    {user ? (
                        <div className="space-y-2">
                            <p><span className="font-medium">ID:</span> {user.user_id}</p>
                            <p><span className="font-medium">用户名:</span> {user.username}</p>
                            <p><span className="font-medium">邮箱:</span> {user.email}</p>
                            <p><span className="font-medium">角色:</span> {user.roles?.join(', ')}</p>
                        </div>
                    ) : (
                        <p>无法获取用户信息</p>
                    )}
                </div>

                <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg border border-blue-100 dark:border-blue-800">
                    <p className="text-blue-800 dark:text-blue-300">
                        这是一个受保护的页面，只有登录后才能访问。您已成功登录并访问该页面。
                    </p>
                </div>
            </div>
        </div>
    );
} 