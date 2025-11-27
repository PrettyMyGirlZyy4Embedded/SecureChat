"""
SecureChat - 端到端加密聊天应用
类似Telegram/WhatsApp的现代化GUI聊天客户端
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import asyncio
import threading
import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path

# 导入P2P客户端模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'client'))
from p2p_client import P2PClient


# 配置信令服务器地址
SIGNALING_SERVER = "ws://66.154.104.100:8765"
APP_NAME = "SecureChat"
APP_VERSION = "1.0.0"


class ModernColors:
    """现代化配色方案（类似Telegram）"""
    PRIMARY = "#0088cc"  # 主色调（蓝色）
    PRIMARY_DARK = "#006699"
    SECONDARY = "#17212b"  # 深色背景
    BACKGROUND = "#ffffff"  # 白色背景
    SIDEBAR = "#f4f4f5"  # 侧边栏灰色
    MESSAGE_SENT = "#dcf8c6"  # 发送消息气泡（绿色）
    MESSAGE_RECEIVED = "#ffffff"  # 接收消息气泡（白色）
    TEXT_PRIMARY = "#000000"
    TEXT_SECONDARY = "#707579"
    ONLINE = "#4caf50"  # 在线状态（绿色）
    BORDER = "#e1e1e1"
    HOVER = "#e8f5e9"


class ChatMessage:
    """聊天消息数据结构"""
    def __init__(self, sender, content, timestamp, is_sent=True, is_encrypted=True):
        self.sender = sender
        self.content = content
        self.timestamp = timestamp
        self.is_sent = is_sent
        self.is_encrypted = is_encrypted
        self.status = "sent"  # sent, delivered, read


class SecureChatApp:
    """主聊天应用"""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)

        # 应用状态
        self.username = None
        self.p2p_client = None
        self.current_chat = None
        self.contacts = {}  # {username: {status, last_seen}}
        self.chat_history = {}  # {username: [messages]}
        self.is_connected = False

        # 异步事件循环
        self.loop = None
        self.async_thread = None

        # 配置文件路径
        self.config_dir = Path.home() / ".securechat"
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "config.json"

        # 加载配置
        self.load_config()

        # 设置样式
        self.setup_styles()

        # 如果已有用户名，直接显示主界面，否则显示登录界面
        if self.username:
            self.show_main_interface()
            self.auto_connect()
        else:
            self.show_login_interface()

    def setup_styles(self):
        """设置现代化样式"""
        style = ttk.Style()
        style.theme_use('clam')

        # 配置按钮样式
        style.configure('Primary.TButton',
                       background=ModernColors.PRIMARY,
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       padding=10)
        style.map('Primary.TButton',
                 background=[('active', ModernColors.PRIMARY_DARK)])

        # 配置框架样式
        style.configure('Sidebar.TFrame', background=ModernColors.SIDEBAR)
        style.configure('Chat.TFrame', background=ModernColors.BACKGROUND)

    def load_config(self):
        """加载配置"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.username = config.get('username')
            except:
                pass

    def save_config(self):
        """保存配置"""
        config = {'username': self.username}
        with open(self.config_file, 'w') as f:
            json.dump(config, f)

    # ==================== 登录界面 ====================

    def show_login_interface(self):
        """显示登录/注册界面"""
        self.clear_window()

        # 创建居中容器
        container = tk.Frame(self.root, bg=ModernColors.BACKGROUND)
        container.place(relx=0.5, rely=0.5, anchor='center')

        # 应用标题
        title = tk.Label(
            container,
            text=APP_NAME,
            font=('Helvetica', 42, 'bold'),
            fg=ModernColors.PRIMARY,
            bg=ModernColors.BACKGROUND
        )
        title.pack(pady=(0, 10))

        # 副标题
        subtitle = tk.Label(
            container,
            text="端到端加密聊天",
            font=('Helvetica', 14),
            fg=ModernColors.TEXT_SECONDARY,
            bg=ModernColors.BACKGROUND
        )
        subtitle.pack(pady=(0, 40))

        # 用户名输入
        username_frame = tk.Frame(container, bg=ModernColors.BACKGROUND)
        username_frame.pack(pady=10)

        tk.Label(
            username_frame,
            text="用户名",
            font=('Helvetica', 12),
            fg=ModernColors.TEXT_PRIMARY,
            bg=ModernColors.BACKGROUND
        ).pack(anchor='w')

        self.username_entry = tk.Entry(
            username_frame,
            font=('Helvetica', 14),
            width=30,
            relief=tk.FLAT,
            bd=2,
            highlightthickness=1,
            highlightbackground=ModernColors.BORDER,
            highlightcolor=ModernColors.PRIMARY
        )
        self.username_entry.pack(pady=(5, 0), ipady=8)
        self.username_entry.focus()

        # 绑定回车键
        self.username_entry.bind('<Return>', lambda e: self.handle_login())

        # 登录按钮
        login_btn = tk.Button(
            container,
            text="开始聊天",
            font=('Helvetica', 14, 'bold'),
            bg=ModernColors.PRIMARY,
            fg='white',
            relief=tk.FLAT,
            padx=60,
            pady=12,
            cursor='hand2',
            command=self.handle_login
        )
        login_btn.pack(pady=30)

        # 提示信息
        info = tk.Label(
            container,
            text="🔐 所有消息端到端加密",
            font=('Helvetica', 10),
            fg=ModernColors.TEXT_SECONDARY,
            bg=ModernColors.BACKGROUND
        )
        info.pack(pady=(20, 0))

    def handle_login(self):
        """处理登录"""
        username = self.username_entry.get().strip()

        if not username:
            messagebox.showerror("错误", "请输入用户名")
            return

        if len(username) < 3:
            messagebox.showerror("错误", "用户名至少3个字符")
            return

        self.username = username
        self.save_config()
        self.show_main_interface()
        self.auto_connect()

    # ==================== 主界面 ====================

    def show_main_interface(self):
        """显示主聊天界面"""
        self.clear_window()

        # 主容器
        main_container = tk.Frame(self.root, bg=ModernColors.BACKGROUND)
        main_container.pack(fill=tk.BOTH, expand=True)

        # 左侧边栏（联系人列表）
        self.create_sidebar(main_container)

        # 右侧聊天区域
        self.create_chat_area(main_container)

        # 状态栏
        self.create_statusbar(main_container)

    def create_sidebar(self, parent):
        """创建侧边栏"""
        sidebar = tk.Frame(parent, bg=ModernColors.SIDEBAR, width=320)
        sidebar.pack(side=tk.LEFT, fill=tk.BOTH)
        sidebar.pack_propagate(False)

        # 顶部用户信息
        user_header = tk.Frame(sidebar, bg=ModernColors.PRIMARY, height=70)
        user_header.pack(fill=tk.X)
        user_header.pack_propagate(False)

        # 用户头像（使用首字母）
        avatar_canvas = tk.Canvas(
            user_header,
            width=50,
            height=50,
            bg=ModernColors.PRIMARY_DARK,
            highlightthickness=0
        )
        avatar_canvas.place(x=15, y=10)

        # 绘制圆形头像
        avatar_canvas.create_oval(2, 2, 48, 48, fill=ModernColors.BACKGROUND, outline='')
        initial = self.username[0].upper() if self.username else "U"
        avatar_canvas.create_text(
            25, 25,
            text=initial,
            font=('Helvetica', 20, 'bold'),
            fill=ModernColors.PRIMARY
        )

        # 用户名
        tk.Label(
            user_header,
            text=self.username or "Guest",
            font=('Helvetica', 16, 'bold'),
            fg='white',
            bg=ModernColors.PRIMARY
        ).place(x=75, y=15)

        # 连接状态
        self.status_label = tk.Label(
            user_header,
            text="● 连接中...",
            font=('Helvetica', 10),
            fg='#ffeb3b',
            bg=ModernColors.PRIMARY
        )
        self.status_label.place(x=75, y=40)

        # 搜索框
        search_frame = tk.Frame(sidebar, bg=ModernColors.SIDEBAR)
        search_frame.pack(fill=tk.X, padx=10, pady=10)

        self.search_entry = tk.Entry(
            search_frame,
            font=('Helvetica', 12),
            relief=tk.FLAT,
            bg=ModernColors.BACKGROUND,
            fg=ModernColors.TEXT_PRIMARY
        )
        self.search_entry.pack(fill=tk.X, ipady=8, padx=5)
        self.search_entry.insert(0, "  🔍 搜索联系人...")
        self.search_entry.bind('<FocusIn>', self.on_search_focus_in)
        self.search_entry.bind('<FocusOut>', self.on_search_focus_out)
        self.search_entry.bind('<KeyRelease>', self.on_search_change)

        # 联系人列表
        list_frame = tk.Frame(sidebar, bg=ModernColors.SIDEBAR)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # 创建滚动画布
        canvas = tk.Canvas(list_frame, bg=ModernColors.SIDEBAR, highlightthickness=0)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        self.contacts_frame = tk.Frame(canvas, bg=ModernColors.SIDEBAR)

        self.contacts_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.contacts_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 绑定鼠标滚轮
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

    def create_chat_area(self, parent):
        """创建聊天区域"""
        chat_container = tk.Frame(parent, bg=ModernColors.BACKGROUND)
        chat_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 聊天头部
        self.chat_header = tk.Frame(chat_container, bg=ModernColors.BACKGROUND, height=70)
        self.chat_header.pack(fill=tk.X)
        self.chat_header.pack_propagate(False)

        # 分隔线
        tk.Frame(self.chat_header, bg=ModernColors.BORDER, height=1).pack(side=tk.BOTTOM, fill=tk.X)

        # 初始显示欢迎消息
        self.welcome_label = tk.Label(
            chat_container,
            text=f"欢迎使用 {APP_NAME}\n\n选择一个联系人开始聊天\n\n🔐 所有消息都经过端到端加密",
            font=('Helvetica', 16),
            fg=ModernColors.TEXT_SECONDARY,
            bg=ModernColors.BACKGROUND,
            justify=tk.CENTER
        )
        self.welcome_label.place(relx=0.5, rely=0.5, anchor='center')

        # 消息显示区域（初始隐藏）
        self.messages_frame = tk.Frame(chat_container, bg=ModernColors.BACKGROUND)

        # 创建消息画布和滚动条
        self.messages_canvas = tk.Canvas(
            self.messages_frame,
            bg=ModernColors.BACKGROUND,
            highlightthickness=0
        )
        messages_scrollbar = tk.Scrollbar(
            self.messages_frame,
            orient="vertical",
            command=self.messages_canvas.yview
        )

        self.messages_container = tk.Frame(self.messages_canvas, bg=ModernColors.BACKGROUND)

        self.messages_container.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        )

        self.messages_canvas.create_window((0, 0), window=self.messages_container, anchor="nw")
        self.messages_canvas.configure(yscrollcommand=messages_scrollbar.set)

        self.messages_canvas.pack(side="left", fill="both", expand=True)
        messages_scrollbar.pack(side="right", fill="y")

        # 输入区域
        self.input_frame = tk.Frame(chat_container, bg=ModernColors.BACKGROUND, height=80)
        self.input_frame.pack_propagate(False)

        # 分隔线
        tk.Frame(self.input_frame, bg=ModernColors.BORDER, height=1).pack(fill=tk.X)

        # 输入框容器
        input_container = tk.Frame(self.input_frame, bg=ModernColors.BACKGROUND)
        input_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # 文件和表情按钮
        buttons_frame = tk.Frame(input_container, bg=ModernColors.BACKGROUND)
        buttons_frame.pack(side=tk.LEFT, padx=(0, 10))

        self.attach_btn = tk.Button(
            buttons_frame,
            text="📎",
            font=('Helvetica', 16),
            bg=ModernColors.BACKGROUND,
            fg=ModernColors.TEXT_SECONDARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self.attach_file
        )
        self.attach_btn.pack(side=tk.LEFT, padx=2)

        self.emoji_btn = tk.Button(
            buttons_frame,
            text="😊",
            font=('Helvetica', 16),
            bg=ModernColors.BACKGROUND,
            fg=ModernColors.TEXT_SECONDARY,
            relief=tk.FLAT,
            cursor='hand2',
            command=self.show_emoji_picker
        )
        self.emoji_btn.pack(side=tk.LEFT, padx=2)

        # 输入框
        self.message_entry = tk.Text(
            input_container,
            font=('Helvetica', 12),
            height=2,
            relief=tk.FLAT,
            bg=ModernColors.BACKGROUND,
            fg=ModernColors.TEXT_PRIMARY,
            wrap=tk.WORD,
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=ModernColors.BORDER,
            highlightcolor=ModernColors.PRIMARY
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
        self.message_entry.bind('<Return>', self.on_enter_pressed)
        self.message_entry.bind('<Shift-Return>', lambda e: None)  # 允许Shift+Enter换行

        # 发送按钮
        self.send_btn = tk.Button(
            input_container,
            text="发送",
            font=('Helvetica', 12, 'bold'),
            bg=ModernColors.PRIMARY,
            fg='white',
            relief=tk.FLAT,
            padx=20,
            cursor='hand2',
            state=tk.DISABLED,
            command=self.send_message
        )
        self.send_btn.pack(side=tk.LEFT)

    def create_statusbar(self, parent):
        """创建状态栏"""
        statusbar = tk.Frame(parent, bg=ModernColors.SIDEBAR, height=25)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_text = tk.Label(
            statusbar,
            text=f"{APP_NAME} v{APP_VERSION} | 端到端加密 🔐",
            font=('Helvetica', 9),
            fg=ModernColors.TEXT_SECONDARY,
            bg=ModernColors.SIDEBAR,
            anchor='w'
        )
        self.status_text.pack(side=tk.LEFT, padx=10)

    # ==================== 联系人管理 ====================

    def add_contact_to_list(self, username, status="offline"):
        """添加联系人到列表"""
        # 检查是否已存在
        for widget in self.contacts_frame.winfo_children():
            if hasattr(widget, 'contact_username') and widget.contact_username == username:
                return

        contact_frame = tk.Frame(
            self.contacts_frame,
            bg=ModernColors.SIDEBAR,
            cursor='hand2'
        )
        contact_frame.pack(fill=tk.X, padx=5, pady=2)
        contact_frame.contact_username = username

        # 悬停效果
        def on_enter(e):
            contact_frame.config(bg=ModernColors.HOVER)
            for child in contact_frame.winfo_children():
                if isinstance(child, (tk.Label, tk.Frame)):
                    child.config(bg=ModernColors.HOVER)

        def on_leave(e):
            bg = ModernColors.PRIMARY if self.current_chat == username else ModernColors.SIDEBAR
            contact_frame.config(bg=bg)
            for child in contact_frame.winfo_children():
                if isinstance(child, (tk.Label, tk.Frame)):
                    child.config(bg=bg)

        contact_frame.bind('<Enter>', on_enter)
        contact_frame.bind('<Leave>', on_leave)
        contact_frame.bind('<Button-1>', lambda e: self.open_chat(username))

        # 头像
        avatar_canvas = tk.Canvas(
            contact_frame,
            width=50,
            height=50,
            bg=ModernColors.SIDEBAR,
            highlightthickness=0
        )
        avatar_canvas.pack(side=tk.LEFT, padx=10, pady=10)
        avatar_canvas.create_oval(2, 2, 48, 48, fill=ModernColors.PRIMARY_DARK, outline='')
        avatar_canvas.create_text(
            25, 25,
            text=username[0].upper(),
            font=('Helvetica', 18, 'bold'),
            fill='white'
        )
        avatar_canvas.bind('<Button-1>', lambda e: self.open_chat(username))

        # 信息区域
        info_frame = tk.Frame(contact_frame, bg=ModernColors.SIDEBAR)
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)
        info_frame.bind('<Button-1>', lambda e: self.open_chat(username))

        # 用户名和状态
        name_frame = tk.Frame(info_frame, bg=ModernColors.SIDEBAR)
        name_frame.pack(fill=tk.X)
        name_frame.bind('<Button-1>', lambda e: self.open_chat(username))

        name_label = tk.Label(
            name_frame,
            text=username,
            font=('Helvetica', 13, 'bold'),
            fg=ModernColors.TEXT_PRIMARY,
            bg=ModernColors.SIDEBAR,
            anchor='w'
        )
        name_label.pack(side=tk.LEFT)
        name_label.bind('<Button-1>', lambda e: self.open_chat(username))

        # 在线状态指示器
        status_indicator = tk.Label(
            name_frame,
            text="●",
            font=('Helvetica', 10),
            fg=ModernColors.ONLINE if status == "online" else ModernColors.TEXT_SECONDARY,
            bg=ModernColors.SIDEBAR
        )
        status_indicator.pack(side=tk.LEFT, padx=5)
        status_indicator.bind('<Button-1>', lambda e: self.open_chat(username))

        # 最后消息预览
        last_msg_label = tk.Label(
            info_frame,
            text="点击开始聊天...",
            font=('Helvetica', 10),
            fg=ModernColors.TEXT_SECONDARY,
            bg=ModernColors.SIDEBAR,
            anchor='w'
        )
        last_msg_label.pack(fill=tk.X, pady=(2, 0))
        last_msg_label.bind('<Button-1>', lambda e: self.open_chat(username))

        self.contacts[username] = {
            'frame': contact_frame,
            'status': status,
            'status_indicator': status_indicator,
            'last_msg_label': last_msg_label
        }

    def update_contacts_list(self, online_users):
        """更新联系人列表"""
        for username in online_users:
            if username != self.username:
                if username not in self.contacts:
                    self.add_contact_to_list(username, "online")
                else:
                    # 更新在线状态
                    self.contacts[username]['status'] = 'online'
                    self.contacts[username]['status_indicator'].config(fg=ModernColors.ONLINE)

    # ==================== 聊天功能 ====================

    def open_chat(self, username):
        """打开与指定用户的聊天"""
        if self.current_chat == username:
            return

        # 更新选中状态
        if self.current_chat and self.current_chat in self.contacts:
            self.contacts[self.current_chat]['frame'].config(bg=ModernColors.SIDEBAR)

        self.current_chat = username
        self.contacts[username]['frame'].config(bg=ModernColors.HOVER)

        # 隐藏欢迎消息
        if hasattr(self, 'welcome_label'):
            self.welcome_label.place_forget()

        # 显示消息区域
        self.messages_frame.pack(fill=tk.BOTH, expand=True)
        self.input_frame.pack(fill=tk.X)

        # 更新聊天头部
        self.update_chat_header(username)

        # 加载聊天历史
        self.load_chat_history(username)

        # 启用输入
        self.send_btn.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.NORMAL)
        self.message_entry.focus()

        # 如果还没连接到这个用户，建立P2P连接
        if self.p2p_client and self.p2p_client.peer_id != username:
            self.connect_to_peer(username)

    def update_chat_header(self, username):
        """更新聊天头部"""
        # 清除旧内容
        for widget in self.chat_header.winfo_children():
            if not isinstance(widget, tk.Frame) or widget.cget('height') != 1:
                widget.destroy()

        # 头像
        avatar_canvas = tk.Canvas(
            self.chat_header,
            width=50,
            height=50,
            bg=ModernColors.BACKGROUND,
            highlightthickness=0
        )
        avatar_canvas.place(x=20, y=10)
        avatar_canvas.create_oval(2, 2, 48, 48, fill=ModernColors.PRIMARY_DARK, outline='')
        avatar_canvas.create_text(
            25, 25,
            text=username[0].upper(),
            font=('Helvetica', 18, 'bold'),
            fill='white'
        )

        # 用户名
        tk.Label(
            self.chat_header,
            text=username,
            font=('Helvetica', 16, 'bold'),
            fg=ModernColors.TEXT_PRIMARY,
            bg=ModernColors.BACKGROUND
        ).place(x=80, y=12)

        # 状态
        status = self.contacts.get(username, {}).get('status', 'offline')
        status_text = "在线" if status == "online" else "离线"
        status_color = ModernColors.ONLINE if status == "online" else ModernColors.TEXT_SECONDARY

        tk.Label(
            self.chat_header,
            text=f"● {status_text}",
            font=('Helvetica', 11),
            fg=status_color,
            bg=ModernColors.BACKGROUND
        ).place(x=80, y=37)

        # 加密指示器
        tk.Label(
            self.chat_header,
            text="🔐 端到端加密",
            font=('Helvetica', 10),
            fg=ModernColors.TEXT_SECONDARY,
            bg=ModernColors.BACKGROUND
        ).place(relx=1.0, x=-20, y=25, anchor='e')

    def load_chat_history(self, username):
        """加载聊天历史"""
        # 清除当前消息
        for widget in self.messages_container.winfo_children():
            widget.destroy()

        # 加载历史消息
        if username in self.chat_history:
            for msg in self.chat_history[username]:
                self.display_message(msg.sender, msg.content, msg.timestamp, msg.is_sent)

    def display_message(self, sender, content, timestamp, is_sent=True):
        """显示消息气泡"""
        # 消息容器
        msg_container = tk.Frame(self.messages_container, bg=ModernColors.BACKGROUND)
        msg_container.pack(fill=tk.X, padx=20, pady=5)

        # 时间戳
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M')

        if is_sent:
            # 发送的消息（右对齐，绿色）
            bubble_frame = tk.Frame(msg_container, bg=ModernColors.BACKGROUND)
            bubble_frame.pack(side=tk.RIGHT)

            # 时间
            tk.Label(
                bubble_frame,
                text=time_str,
                font=('Helvetica', 9),
                fg=ModernColors.TEXT_SECONDARY,
                bg=ModernColors.BACKGROUND
            ).pack(side=tk.RIGHT, padx=(10, 0), pady=5)

            # 消息气泡
            bubble = tk.Label(
                bubble_frame,
                text=content,
                font=('Helvetica', 12),
                fg=ModernColors.TEXT_PRIMARY,
                bg=ModernColors.MESSAGE_SENT,
                padx=15,
                pady=10,
                wraplength=400,
                justify=tk.LEFT,
                relief=tk.FLAT
            )
            bubble.pack(side=tk.RIGHT)

        else:
            # 接收的消息（左对齐，白色）
            bubble_frame = tk.Frame(msg_container, bg=ModernColors.BACKGROUND)
            bubble_frame.pack(side=tk.LEFT)

            # 头像
            avatar_canvas = tk.Canvas(
                bubble_frame,
                width=35,
                height=35,
                bg=ModernColors.BACKGROUND,
                highlightthickness=0
            )
            avatar_canvas.pack(side=tk.LEFT, padx=(0, 10))
            avatar_canvas.create_oval(2, 2, 33, 33, fill=ModernColors.PRIMARY_DARK, outline='')
            avatar_canvas.create_text(
                17, 17,
                text=sender[0].upper(),
                font=('Helvetica', 14, 'bold'),
                fill='white'
            )

            # 消息内容框
            content_frame = tk.Frame(bubble_frame, bg=ModernColors.BACKGROUND)
            content_frame.pack(side=tk.LEFT)

            # 发送者名字
            tk.Label(
                content_frame,
                text=sender,
                font=('Helvetica', 10, 'bold'),
                fg=ModernColors.PRIMARY,
                bg=ModernColors.BACKGROUND,
                anchor='w'
            ).pack(anchor='w')

            # 消息气泡
            bubble = tk.Label(
                content_frame,
                text=content,
                font=('Helvetica', 12),
                fg=ModernColors.TEXT_PRIMARY,
                bg=ModernColors.MESSAGE_RECEIVED,
                padx=15,
                pady=10,
                wraplength=400,
                justify=tk.LEFT,
                relief=tk.SOLID,
                borderwidth=1
            )
            bubble.pack(anchor='w')
            bubble.config(highlightbackground=ModernColors.BORDER, highlightthickness=1)

            # 时间
            tk.Label(
                content_frame,
                text=time_str,
                font=('Helvetica', 9),
                fg=ModernColors.TEXT_SECONDARY,
                bg=ModernColors.BACKGROUND,
                anchor='w'
            ).pack(anchor='w', pady=(2, 0))

        # 自动滚动到底部
        self.messages_canvas.update_idletasks()
        self.messages_canvas.yview_moveto(1.0)

    def on_enter_pressed(self, event):
        """处理回车键"""
        # Shift+Enter换行，Enter发送
        if event.state & 0x1:  # Shift键被按下
            return
        else:
            self.send_message()
            return 'break'  # 阻止默认行为

    def send_message(self):
        """发送消息"""
        if not self.current_chat:
            return

        content = self.message_entry.get("1.0", tk.END).strip()
        if not content:
            return

        # 显示消息
        timestamp = time.time()
        self.display_message(self.username, content, timestamp, is_sent=True)

        # 保存到历史
        if self.current_chat not in self.chat_history:
            self.chat_history[self.current_chat] = []

        msg = ChatMessage(self.username, content, timestamp, is_sent=True)
        self.chat_history[self.current_chat].append(msg)

        # 更新联系人列表的最后消息
        if self.current_chat in self.contacts:
            self.contacts[self.current_chat]['last_msg_label'].config(
                text=content[:30] + "..." if len(content) > 30 else content
            )

        # 清空输入框
        self.message_entry.delete("1.0", tk.END)

        # 通过P2P发送
        if self.p2p_client and self.p2p_client.peer_id == self.current_chat:
            asyncio.run_coroutine_threadsafe(
                self.p2p_client.send_message(content),
                self.loop
            )

        # 播放发送音效（可选）
        self.play_send_sound()

    def receive_message(self, sender, content):
        """接收消息"""
        timestamp = time.time()

        # 保存到历史
        if sender not in self.chat_history:
            self.chat_history[sender] = []

        msg = ChatMessage(sender, content, timestamp, is_sent=False)
        self.chat_history[sender].append(msg)

        # 如果正在和发送者聊天，显示消息
        if self.current_chat == sender:
            self.display_message(sender, content, timestamp, is_sent=False)

        # 更新联系人列表
        if sender in self.contacts:
            self.contacts[sender]['last_msg_label'].config(
                text=content[:30] + "..." if len(content) > 30 else content
            )

        # 播放接收音效
        self.play_receive_sound()

        # 显示通知
        self.show_notification(sender, content)

    # ==================== 辅助功能 ====================

    def attach_file(self):
        """附加文件"""
        if not self.current_chat:
            return

        filepath = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[("所有文件", "*.*")]
        )

        if filepath:
            filename = Path(filepath).name
            # 显示文件发送消息
            self.display_message(
                self.username,
                f"📎 {filename}",
                time.time(),
                is_sent=True
            )
            # TODO: 实现文件传输

    def show_emoji_picker(self):
        """显示表情选择器"""
        emojis = ["😊", "😂", "❤️", "👍", "🎉", "🔥", "✨", "💯", "🙏", "👏"]

        # 创建弹出窗口
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("选择表情")
        emoji_window.geometry("250x100")
        emoji_window.resizable(False, False)

        frame = tk.Frame(emoji_window)
        frame.pack(padx=10, pady=10)

        for i, emoji in enumerate(emojis):
            btn = tk.Button(
                frame,
                text=emoji,
                font=('Helvetica', 20),
                relief=tk.FLAT,
                command=lambda e=emoji: self.insert_emoji(e, emoji_window)
            )
            btn.grid(row=i//5, column=i%5, padx=5, pady=5)

    def insert_emoji(self, emoji, window):
        """插入表情"""
        self.message_entry.insert(tk.INSERT, emoji)
        window.destroy()
        self.message_entry.focus()

    def on_search_focus_in(self, event):
        """搜索框获得焦点"""
        if self.search_entry.get() == "  🔍 搜索联系人...":
            self.search_entry.delete(0, tk.END)

    def on_search_focus_out(self, event):
        """搜索框失去焦点"""
        if not self.search_entry.get():
            self.search_entry.insert(0, "  🔍 搜索联系人...")

    def on_search_change(self, event):
        """搜索内容改变"""
        search_text = self.search_entry.get().lower()
        if search_text == "  🔍 搜索联系人...":
            return

        # 过滤联系人列表
        for username, contact_info in self.contacts.items():
            if search_text in username.lower():
                contact_info['frame'].pack(fill=tk.X, padx=5, pady=2)
            else:
                contact_info['frame'].pack_forget()

    def play_send_sound(self):
        """播放发送音效"""
        # TODO: 实现音效
        pass

    def play_receive_sound(self):
        """播放接收音效"""
        # TODO: 实现音效
        pass

    def show_notification(self, sender, content):
        """显示系统通知"""
        # 更新标题栏显示新消息
        if self.current_chat != sender:
            self.root.title(f"({sender}) {APP_NAME}")
            # 5秒后恢复标题
            self.root.after(5000, lambda: self.root.title(f"{APP_NAME} v{APP_VERSION}"))

    # ==================== P2P连接 ====================

    def auto_connect(self):
        """自动连接到信令服务器"""
        self.async_thread = threading.Thread(target=self.run_async_loop, daemon=True)
        self.async_thread.start()

    def run_async_loop(self):
        """运行异步事件循环"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.connect_to_server())

    async def connect_to_server(self):
        """连接到信令服务器"""
        try:
            self.p2p_client = P2PClient(self.username, SIGNALING_SERVER)

            # 设置消息回调
            self.p2p_client.on_message(lambda msg: self.root.after(0, self.receive_message, self.p2p_client.peer_id, msg))

            # 连接服务器
            await self.p2p_client.connect_to_signaling_server()

            self.is_connected = True
            self.root.after(0, self.update_connection_status, True)

            # 获取在线用户
            online_users = await self.p2p_client.list_online_clients()
            self.root.after(0, self.update_contacts_list, list(online_users.keys()))

            # 保持连接
            await self.p2p_client.handle_signaling_messages()

        except Exception as e:
            print(f"Connection error: {e}")
            self.root.after(0, self.update_connection_status, False)
            # 5秒后重连
            await asyncio.sleep(5)
            await self.connect_to_server()

    def connect_to_peer(self, username):
        """连接到对等节点"""
        if self.p2p_client and self.is_connected:
            asyncio.run_coroutine_threadsafe(
                self.p2p_client.connect_to_peer(username),
                self.loop
            )

    def update_connection_status(self, connected):
        """更新连接状态"""
        if connected:
            self.status_label.config(text="● 已连接", fg=ModernColors.ONLINE)
            self.status_text.config(text=f"{APP_NAME} v{APP_VERSION} | 已连接 🔐")
        else:
            self.status_label.config(text="● 连接中...", fg='#ffeb3b')
            self.status_text.config(text=f"{APP_NAME} v{APP_VERSION} | 连接中...")

    # ==================== 工具方法 ====================

    def clear_window(self):
        """清空窗口"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def on_closing(self):
        """关闭应用"""
        if self.p2p_client:
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.p2p_client.disconnect(), self.loop)
        self.root.destroy()


def main():
    """主函数"""
    root = tk.Tk()
    app = SecureChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()
