/** @type {import('next').NextConfig} */
const nextConfig = {
    // 基于环境变量确定是否使用静态导出
    ...(process.env.NEXT_PUBLIC_STATIC_EXPORT === 'true' ?
        {
            // 静态导出配置
            output: 'export',
            // 没有使用图像优化
            images: { unoptimized: true },
        } :
        {
            // 开发环境配置 - 包含API代理
            async rewrites() {
                // 使用环境变量设置API地址，默认指向8001端口
                const apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:8001';
                console.log(`API requests will be proxied to: ${apiBaseUrl}`);

                return [
                    {
                        source: '/api/:path*',
                        destination: `${apiBaseUrl}/api/:path*`,
                    },
                ];
            }
        }
    ),
    // 关闭严格模式，避免开发中的双重渲染
    reactStrictMode: false,
};

console.log("Next.js配置模式:", process.env.NEXT_PUBLIC_STATIC_EXPORT === 'true' ? '静态导出' : '开发模式(含API代理)');

module.exports = nextConfig; 