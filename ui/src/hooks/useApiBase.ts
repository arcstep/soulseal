/**
 * API基础URL管理Hook - 提供API基础URL
 * 
 * 根据环境变量返回适当的API基础URL
 */
export function useApiBase() {
    // 从环境变量获取API基础URL，如果未设置则使用相对路径
    const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || '';

    return {
        API_BASE_URL
    };
} 