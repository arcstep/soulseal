export default function TestPage() {
    return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-r from-blue-500 to-purple-600 p-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8 max-w-md w-full">
                <h1 className="text-3xl font-bold text-center text-gray-900 dark:text-white mb-6">
                    Tailwind CSS 测试
                </h1>
                <p className="text-gray-700 dark:text-gray-300 mb-4">
                    这个页面用于测试Tailwind CSS是否正常工作。如果你能看到颜色、阴影和排版样式，说明Tailwind已经正确配置。
                </p>
                <div className="flex space-x-4 mt-6">
                    <button className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-md transition-colors duration-300 flex-1">
                        按钮1
                    </button>
                    <button className="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded-md transition-colors duration-300 flex-1">
                        按钮2
                    </button>
                </div>
                <div className="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                    <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">颜色测试</h2>
                    <div className="grid grid-cols-4 gap-2">
                        <div className="h-10 bg-red-500 rounded"></div>
                        <div className="h-10 bg-green-500 rounded"></div>
                        <div className="h-10 bg-blue-500 rounded"></div>
                        <div className="h-10 bg-yellow-500 rounded"></div>
                    </div>
                </div>
            </div>
        </div>
    );
} 