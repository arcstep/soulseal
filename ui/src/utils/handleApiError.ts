/**
 * 处理API认证错误，如果需要，重定向到登录页面
 * 
 * @param status HTTP状态码
 * @param message 可选的错误消息
 * @returns 是否已处理
 */
export function handleAuthError(status: number, message?: string): boolean {
    if (status === 401) {
        // 获取当前路径
        const currentPath = window.location.pathname;
        // 登录页面不需要重定向
        if (currentPath !== '/login') {
            window.location.href = `/login?from=${encodeURIComponent(currentPath)}`;
        }

        if (message) {
            console.error(message);
        } else {
            console.error('未登录或会话已过期');
        }

        return true;
    }

    return false;
}

/**
 * 检查并处理常见的API错误
 * 
 * @param error 捕获的错误对象
 * @param defaultMessage 默认错误信息
 * @returns 是否已处理特殊错误
 */
export function handleApiError(error: unknown, defaultMessage: string = '请求失败'): boolean {
    console.error(defaultMessage, error);

    // 处理Response对象
    if (error instanceof Response) {
        return handleAuthError(error.status, `${defaultMessage}: HTTP ${error.status}`);
    }

    // 处理包含Response属性的错误对象
    if (error && typeof error === 'object' && 'response' in error) {
        const response = (error as any).response;
        if (response && typeof response === 'object' && 'status' in response) {
            return handleAuthError(response.status, `${defaultMessage}: HTTP ${response.status}`);
        }
    }

    // 处理网络错误
    if (error instanceof Error) {
        if (error.name === 'NetworkError' || error.message.includes('network')) {
            console.error('网络连接错误，请检查您的网络连接');
            return true;
        }
    }

    return false;
} 