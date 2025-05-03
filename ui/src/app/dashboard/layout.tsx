'use client';

import { ReactNode, Suspense } from 'react';

export default function DashboardLayout({
    children,
}: {
    children: ReactNode;
}) {
    return (
        <Suspense fallback={<div className="flex items-center justify-center h-screen">加载中...</div>}>
            {children}
        </Suspense>
    );
} 