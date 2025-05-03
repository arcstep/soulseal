'use client';

import { ReactNode, Suspense } from 'react';

export default function AuthLayout({
    children,
}: {
    children: ReactNode;
}) {
    return (
        <Suspense fallback={<div className="flex items-center justify-center h-screen">加载中...</div>}>
            <div className="min-h-screen">
                {children}
            </div>
        </Suspense>
    );
}