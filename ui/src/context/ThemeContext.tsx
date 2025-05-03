'use client';

import { createContext, useState, useContext, useEffect, ReactNode } from 'react';

export type ThemeMode = 'light' | 'dark' | 'system';

interface ThemeContextType {
    theme: ThemeMode;
    setTheme: (theme: ThemeMode) => void;
    isSystemDark: boolean; // 系统是否为暗色模式
    resolvedTheme: 'light' | 'dark'; // 最终应用的主题（考虑system设置）
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

// 改为可配置的本地存储key，便于集成
export const THEME_STORAGE_KEY = 'theme-preference';

export function ThemeProvider({
    children,
    storageKey = THEME_STORAGE_KEY // 允许通过props自定义存储键名
}: {
    children: ReactNode;
    storageKey?: string;
}) {
    // 确定初始主题
    const [theme, setThemeState] = useState<ThemeMode>(() => {
        // 客户端：从localStorage获取
        if (typeof window !== 'undefined') {
            try {
                const storedTheme = localStorage.getItem(storageKey) as ThemeMode;
                if (storedTheme && ['light', 'dark', 'system'].includes(storedTheme)) {
                    return storedTheme;
                }
            } catch (error) {
                console.error('读取主题设置失败:', error);
            }
        }
        return 'system'; // 默认跟随系统
    });

    // 检测系统主题偏好
    const [isSystemDark, setIsSystemDark] = useState<boolean>(false);

    // 最终确定的主题
    const resolvedTheme = theme === 'system' ? (isSystemDark ? 'dark' : 'light') : theme;

    // 设置主题的封装函数
    const setTheme = (newTheme: ThemeMode) => {
        setThemeState(newTheme);
        try {
            localStorage.setItem(storageKey, newTheme);
        } catch (error) {
            console.error('保存主题设置失败:', error);
        }
    };

    // 监听系统主题变化
    useEffect(() => {
        function updateSystemTheme() {
            const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            setIsSystemDark(isDark);
        }

        // 初始检测
        updateSystemTheme();

        // 监听系统主题变化
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

        // 使用回调函数处理变化
        const handleChange = () => updateSystemTheme();

        // 添加事件监听器，兼容现代浏览器和旧浏览器
        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', handleChange);
        } else if ('addListener' in mediaQuery) {
            // @ts-ignore - 旧API，TypeScript不再支持
            mediaQuery.addListener(handleChange);
        }

        // 清理监听器
        return () => {
            if (mediaQuery.removeEventListener) {
                mediaQuery.removeEventListener('change', handleChange);
            } else if ('removeListener' in mediaQuery) {
                // @ts-ignore - 旧API
                mediaQuery.removeListener(handleChange);
            }
        };
    }, []);

    // 监听localStorage变化，实现跨应用集成
    useEffect(() => {
        // 处理localStorage变化事件
        const handleStorageChange = (e: StorageEvent) => {
            if (e.key === storageKey && e.newValue) {
                if (['light', 'dark', 'system'].includes(e.newValue)) {
                    setThemeState(e.newValue as ThemeMode);
                }
            }
        };

        // 添加storage事件监听
        window.addEventListener('storage', handleStorageChange);

        // 清理事件监听
        return () => {
            window.removeEventListener('storage', handleStorageChange);
        };
    }, [storageKey]);

    // 应用主题到HTML元素
    useEffect(() => {
        document.documentElement.classList.remove('light', 'dark');
        document.documentElement.classList.add(resolvedTheme);

        // 额外兼容：设置data-theme属性，某些库使用这个
        document.documentElement.setAttribute('data-theme', resolvedTheme);
    }, [resolvedTheme]);

    return (
        <ThemeContext.Provider value={{ theme, setTheme, isSystemDark, resolvedTheme }}>
            {children}
        </ThemeContext.Provider>
    );
}

// 自定义Hook，方便在组件中使用
export function useTheme() {
    const context = useContext(ThemeContext);
    if (context === undefined) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    return context;
} 