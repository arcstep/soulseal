'use client';

import { useRouter } from 'next/navigation';
import Image from "next/image";

export default function Home() {
  const router = useRouter();

  return (
    <div className="grid grid-rows-[20px_1fr_20px] items-center justify-items-center min-h-screen p-8 pb-20 gap-16 sm:p-20 font-[family-name:var(--font-geist-sans)]">
      <main className="flex flex-col gap-[32px] row-start-2 items-center sm:items-start">
        <h1 className="text-4xl font-bold mb-4">SoulSeal 安全身份验证</h1>

        <p className="text-lg mb-8 max-w-2xl text-center sm:text-left">
          SoulSeal是一个高安全性、高性能的身份验证系统，使用现代化技术栈构建，
          提供安全可靠的用户认证体验。
        </p>

        <div className="flex gap-4 items-center flex-col sm:flex-row">
          <button
            className="rounded-full border border-solid border-transparent transition-colors flex items-center justify-center bg-foreground text-background gap-2 hover:bg-[#383838] dark:hover:bg-[#ccc] font-medium text-sm sm:text-base h-10 sm:h-12 px-4 sm:px-5 sm:w-auto"
            onClick={() => router.push('/login')}
          >
            登录系统
          </button>
          <button
            className="rounded-full border border-solid border-black/[.08] dark:border-white/[.145] transition-colors flex items-center justify-center hover:bg-[#f2f2f2] dark:hover:bg-[#1a1a1a] hover:border-transparent font-medium text-sm sm:text-base h-10 sm:h-12 px-4 sm:px-5 w-full sm:w-auto"
            onClick={() => router.push('/dashboard')}
          >
            查看仪表板
          </button>
        </div>

        <div className="mt-8 p-6 bg-gray-100 dark:bg-gray-800 rounded-lg max-w-2xl">
          <h2 className="text-xl font-semibold mb-4">系统特点：</h2>
          <ul className="list-disc pl-5 space-y-2">
            <li>基于JWT的无状态认证</li>
            <li>刷新令牌机制，支持自动续期</li>
            <li>安全的密码存储</li>
            <li>基于角色的访问控制</li>
            <li>多设备同时登录支持</li>
            <li>黑名单机制，支持令牌撤销</li>
          </ul>
        </div>
      </main>

      <footer className="row-start-3 text-sm text-gray-500">
        © {new Date().getFullYear()} SoulSeal 系统
      </footer>
    </div>
  );
}
