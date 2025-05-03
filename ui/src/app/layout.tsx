'use client';

import { AuthProvider } from '@/context/AuthContext';
import { ThemeProvider } from '@/context/ThemeContext';
import "./globals.css";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="zh">
      <head>
        <title>SoulSeal - 安全身份验证</title>
        <meta name="description" content="SoulSeal 安全身份验证系统" />
      </head>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <ThemeProvider storageKey="theme-preference">
          <AuthProvider>
            {children}
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
