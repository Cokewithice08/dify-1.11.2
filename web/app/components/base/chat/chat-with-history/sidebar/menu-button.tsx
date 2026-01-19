import React, { useState, useRef, useEffect } from 'react';
import Avatar from '@/app/components/base/avatar'
import Cookies from 'js-cookie'
const MenuButton = () => {
    const [isOpen, setIsOpen] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);
    const buttonRef = useRef<HTMLButtonElement>(null);

    // 点击外部关闭菜单
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
                if (buttonRef.current && !buttonRef.current.contains(event.target as Node)) {
                    setIsOpen(false);
                }
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);

    // 菜单项数据
    const menuItems = [
        { id: 1, label: '退出登录' }
    ];
    // const gree_mail = localStorage.getItem('gree_mail')
    // const gree_token = localStorage.getItem('gree_token')
    const gree_mail = Cookies.get('gree_mail')
    const gree_token = Cookies.get('gree_token')
    const argument = Cookies.get('argument')
  
    return (
        <div className="relative">
            {/* 合并后的按钮 */}
            <button
                ref={buttonRef}
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-2 p-1 pr-3 rounded-full hover:bg-transparent focus:outline-none"
            >
                {/* 头像部分 */}
                <div className="flex items-center justify-center w-10 h-10 rounded-full bg-gray-100">
                    <Avatar avatar={'gree'} name={'gree'} size={32} />
                </div>

                {/* 文字部分 */}
                <div className="text-sm">{gree_mail}</div>
            </button>
            {/* 菜单内容 */}
            {isOpen && (
                <div
                    ref={menuRef}
                    className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-48 bg-white rounded-md shadow-lg py-1 z-50"
                >
                    {menuItems.map((item) => (
                        <button
                            key={item.id}
                            className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                            onClick={() => {
                                // 清除这个gree_mail
                                Cookies.remove("gree_mail",{
                                    path: '/'
                                })
                                // localStorage.removeItem('gree_mail')
                                if (gree_token) {
                                    //localStorage.removeItem('gree_token')
                                    Cookies.remove("gree_token",{
                                        path: '/'
                                    })
                                }
                                setIsOpen(false);
                                window.location.reload();
                            }}
                        >
                            {item.label}
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
};

export default MenuButton;