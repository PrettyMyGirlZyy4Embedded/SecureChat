#!/usr/bin/env python3
"""
SecureChat 增强版客户端 - 集成军事级安全 + P2P网络通信
- PKI证书认证
- 多因素认证（MFA）
- 证书指纹验证
- 信任管理
- P2P实时通信
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import sys
import os
from pathlib import Path
import json
import time
import asyncio
import threading
import websockets
from datetime import datetime

# 添加模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'client'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'common'))

from pki_manager import CertificateAuthority, SecureKeyStore, TrustManager
from mfa_module import MFAManager
from crypto_module import CryptoManager
from security_policy import SecurityPolicy, SecurityLevel, InputValidator, ValidationError
from cryptography.hazmat.primitives import serialization

# 信令服务器配置
SIGNALING_SERVER = "ws://66.154.104.100:8765"


class SecureChatClient:
    """增强版安全聊天客户端"""

    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat - 军事级安全 + P2P网络")
        self.root.geometry("1000x700")

        # 配置目录
        self.config_dir = Path.home() / ".securechat_military"
        self.config_dir.mkdir(exist_ok=True)

        self.ca_dir = self.config_dir / "ca"
        self.keys_dir = self.config_dir / "keys"
        self.mfa_dir = self.config_dir / "mfa"
        self.trust_dir = self.config_dir / "trust"

        # 状态
        self.username = None
        self.keystore = None
        self.crypto = None
        self.mfa = None
        self.trust_manager = None
        self.ca = None
        self.current_peer = None

        # 网络状态
        self.ws = None  # WebSocket连接
        self.is_connected = False
        self.online_users = {}

        # 异步事件循环
        self.loop = None
        self.async_thread = None

        # 聊天历史
        self.chat_history = {}

        # 加载或创建CA
        self.load_or_create_ca()

        # 显示登录界面
        self.show_login_screen()

        # 注册关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_or_create_ca(self):
        """加载或创建CA"""
        try:
            self.ca = CertificateAuthority("SecureChat-CA", self.ca_dir)
        except Exception as e:
            messagebox.showerror("错误", f"CA初始化失败: {e}")
            sys.exit(1)

    def show_login_screen(self):
        """显示登录界面"""
        self.clear_window()

        # 主容器
        container = tk.Frame(self.root, bg='#f0f0f0')
        container.place(relx=0.5, rely=0.5, anchor='center')

        # 标题
        tk.Label(
            container,
            text="🔒 SecureChat",
            font=('Arial', 32, 'bold'),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(pady=20)

        tk.Label(
            container,
            text="军事级端到端加密聊天",
            font=('Arial', 12),
            bg='#f0f0f0',
            fg='#7f8c8d'
        ).pack(pady=(0, 30))

        # 用户名输入
        tk.Label(
            container,
            text="用户名",
            font=('Arial', 11),
            bg='#f0f0f0',
            fg='#2c3e50'
        ).pack(anchor='w', padx=20)

        self.username_entry = tk.Entry(
            container,
            font=('Arial', 12),
            width=30,
            relief=tk.FLAT,
            bd=2
        )
        self.username_entry.pack(pady=(5, 20), padx=20, ipady=8)
        self.username_entry.bind('<Return>', lambda e: self.handle_login())

        # 登录按钮
        tk.Button(
            container,
            text="登录 / 注册",
            font=('Arial', 12, 'bold'),
            bg='#3498db',
            fg='white',
            relief=tk.FLAT,
            padx=40,
            pady=10,
            cursor='hand2',
            command=self.handle_login
        ).pack(pady=10)

        # 安全提示
        info_frame = tk.Frame(container, bg='#ecf0f1', relief=tk.FLAT, bd=1)
        info_frame.pack(pady=20, padx=20, fill='x')

        tk.Label(
            info_frame,
            text="🛡️ 安全特性",
            font=('Arial', 10, 'bold'),
            bg='#ecf0f1',
            fg='#2c3e50'
        ).pack(pady=(10, 5))

        features = [
            "✓ PKI证书身份认证",
            "✓ AES-256-GCM端到端加密",
            "✓ 多因素认证 (MFA)",
            "✓ 防重放攻击保护"
        ]

        for feature in features:
            tk.Label(
                info_frame,
                text=feature,
                font=('Arial', 9),
                bg='#ecf0f1',
                fg='#34495e'
            ).pack(anchor='w', padx=20, pady=2)

        tk.Label(
            info_frame,
            text="",
            bg='#ecf0f1'
        ).pack(pady=5)

    def handle_login(self):
        """处理登录"""
        username = self.username_entry.get().strip()

        # 验证用户名
        try:
            username = InputValidator.validate_username(username)
        except ValidationError as e:
            messagebox.showerror("验证失败", str(e))
            return

        self.username = username

        # 检查是否是新用户
        user_keys_dir = self.keys_dir / username
        is_new_user = not user_keys_dir.exists()

        if is_new_user:
            self.register_new_user()
        else:
            self.login_existing_user()

    def register_new_user(self):
        """注册新用户"""
        # 显示进度窗口
        progress_window = tk.Toplevel(self.root)
        progress_window.title("注册中...")
        progress_window.geometry("400x300")
        progress_window.transient(self.root)
        progress_window.grab_set()

        text = scrolledtext.ScrolledText(
            progress_window,
            font=('Courier', 10),
            wrap=tk.WORD
        )
        text.pack(fill='both', expand=True, padx=10, pady=10)

        def log(msg):
            text.insert(tk.END, msg + "\n")
            text.see(tk.END)
            progress_window.update()

        try:
            log("🔐 正在生成密钥...")

            # 创建密钥存储
            self.keystore = SecureKeyStore(self.username, self.keys_dir)
            self.keystore.generate_keys()

            # 获取密码
            password = self.get_password_dialog("设置密钥密码（至少16字符）")
            if not password:
                progress_window.destroy()
                return

            # 保存密钥
            self.keystore.save_keys(password=password)
            log("✓ 密钥已生成并加密保存")

            # 颁发证书
            log("\n📜 正在申请证书...")
            certificate, fingerprint = self.ca.issue_client_certificate(
                client_id=self.username,
                client_public_key=self.keystore.verify_key,
                validity_days=365
            )
            self.keystore.save_certificate(certificate, fingerprint)
            log(f"✓ 证书已颁发")
            log(f"  指纹: {fingerprint}")

            # 设置MFA
            log("\n🔑 正在设置多因素认证...")
            self.mfa = MFAManager(self.username, self.mfa_dir)
            secret, uri, recovery_codes = self.mfa.setup_totp()

            log("✓ MFA密钥已生成")
            log(f"\n请使用认证器应用扫描二维码或手动输入密钥:")
            log(f"密钥: {secret}")

            # 显示恢复码
            log(f"\n⚠️ 恢复码（请安全保存）：")
            for i, code in enumerate(recovery_codes, 1):
                log(f"  {i:2d}. {code}")

            # 等待用户准备好
            tk.Button(
                progress_window,
                text="我已保存恢复码，继续",
                command=lambda: progress_window.quit()
            ).pack(pady=10)

            progress_window.wait_window()

            # 验证MFA
            self.verify_mfa_setup()

            progress_window.destroy()

            # 初始化加密
            self.init_crypto()

            # 初始化信任管理
            self.trust_manager = TrustManager(self.username, self.trust_dir)

            # 显示主界面
            self.show_main_screen()

            messagebox.showinfo(
                "注册成功",
                f"欢迎, {self.username}!\n\n"
                f"您的账户已设置完成，包括：\n"
                f"✓ PKI证书\n"
                f"✓ 加密密钥\n"
                f"✓ 多因素认证\n\n"
                f"证书指纹: {fingerprint[:16]}..."
            )

        except Exception as e:
            progress_window.destroy()
            messagebox.showerror("注册失败", str(e))
            import traceback
            traceback.print_exc()

    def login_existing_user(self):
        """登录现有用户"""
        try:
            # 加载密钥
            self.keystore = SecureKeyStore(self.username, self.keys_dir)

            # 获取密码
            password = self.get_password_dialog("输入密钥密码")
            if not password:
                return

            # 加载密钥
            try:
                self.keystore.load_keys(password=password)
            except Exception:
                messagebox.showerror("错误", "密码错误")
                return

            # 自动生成缺失的 DH 公钥文件（向后兼容）
            if not self.keystore.dh_public_key_path.exists() and self.keystore.dh_public_key:
                try:
                    dh_public_pem = self.keystore.dh_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    self.keystore.dh_public_key_path.write_bytes(dh_public_pem)
                    print(f"✓ 已自动生成 DH 公钥文件: {self.keystore.dh_public_key_path}")
                except Exception as e:
                    print(f"警告: 无法生成 DH 公钥文件: {e}")

            # 加载证书
            self.keystore.load_certificate()

            # 验证证书
            if not self.ca.verify_certificate(self.keystore.certificate):
                messagebox.showerror("错误", "证书验证失败")
                return

            # 加载MFA
            self.mfa = MFAManager(self.username, self.mfa_dir)

            # MFA验证
            if self.mfa.is_enabled():
                otp = simpledialog.askstring(
                    "多因素认证",
                    "请输入认证器中的6位数字:",
                    parent=self.root
                )

                if not otp:
                    return

                success, message = self.mfa.verify_login(otp)
                if not success:
                    messagebox.showerror("MFA验证失败", message)
                    return

            # 初始化加密
            self.init_crypto()

            # 初始化信任管理
            self.trust_manager = TrustManager(self.username, self.trust_dir)

            # 显示主界面
            self.show_main_screen()

        except Exception as e:
            messagebox.showerror("登录失败", str(e))
            import traceback
            traceback.print_exc()

    def verify_mfa_setup(self):
        """验证MFA设置"""
        while True:
            otp = simpledialog.askstring(
                "验证MFA",
                "请输入认证器中显示的6位数字:",
                parent=self.root
            )

            if not otp:
                return

            if self.mfa.verify_and_enable(otp):
                messagebox.showinfo("成功", "MFA已启用")
                break
            else:
                messagebox.showerror("错误", "OTP验证失败，请重试")

    def init_crypto(self):
        """初始化加密管理器"""
        self.crypto = CryptoManager(self.username)
        self.crypto.signing_key = self.keystore.signing_key
        self.crypto.verify_key = self.keystore.verify_key
        self.crypto.dh_private_key = self.keystore.dh_private_key
        self.crypto.dh_public_key = self.keystore.dh_public_key

    def show_main_screen(self):
        """显示主界面"""
        self.clear_window()

        # 主容器
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True)

        # 顶部工具栏
        toolbar = tk.Frame(main_frame, bg='#34495e', height=50)
        toolbar.pack(fill='x')

        tk.Label(
            toolbar,
            text=f"🔒 {self.username}",
            font=('Arial', 12, 'bold'),
            bg='#34495e',
            fg='white'
        ).pack(side='left', padx=20, pady=10)

        # 证书指纹
        if self.keystore.certificate_fingerprint:
            tk.Label(
                toolbar,
                text=f"证书指纹: {self.keystore.certificate_fingerprint[:16]}...",
                font=('Arial', 9),
                bg='#34495e',
                fg='#bdc3c7'
            ).pack(side='left', padx=10)

        # 右侧按钮
        tk.Button(
            toolbar,
            text="注销",
            command=self.logout,
            bg='#e74c3c',
            fg='white',
            relief=tk.FLAT,
            padx=15,
            pady=5
        ).pack(side='right', padx=10)

        # 主内容区域
        content = tk.Frame(main_frame)
        content.pack(fill='both', expand=True)

        # 左侧 - 对等节点输入
        left_panel = tk.Frame(content, bg='#ecf0f1', width=300)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)
        left_panel.pack_propagate(False)

        tk.Label(
            left_panel,
            text="连接到对等节点",
            font=('Arial', 12, 'bold'),
            bg='#ecf0f1'
        ).pack(pady=10)

        tk.Label(
            left_panel,
            text="对方用户名:",
            font=('Arial', 10),
            bg='#ecf0f1'
        ).pack(anchor='w', padx=10)

        self.peer_entry = tk.Entry(
            left_panel,
            font=('Arial', 11),
            relief=tk.FLAT,
            bd=2
        )
        self.peer_entry.pack(fill='x', padx=10, pady=5, ipady=5)

        tk.Button(
            left_panel,
            text="建立安全连接",
            command=self.connect_to_peer,
            bg='#3498db',
            fg='white',
            relief=tk.FLAT,
            pady=8
        ).pack(fill='x', padx=10, pady=10)

        # 信任的对等节点列表
        tk.Label(
            left_panel,
            text="信任的对等节点:",
            font=('Arial', 10, 'bold'),
            bg='#ecf0f1'
        ).pack(anchor='w', padx=10, pady=(20, 5))

        self.trusted_peers_list = tk.Listbox(
            left_panel,
            font=('Arial', 10),
            relief=tk.FLAT,
            bd=1
        )
        self.trusted_peers_list.pack(fill='both', expand=True, padx=10, pady=5)
        self.trusted_peers_list.bind('<Double-Button-1>', self.on_peer_double_click)

        self.refresh_trusted_peers()

        # 右侧 - 聊天区域
        right_panel = tk.Frame(content)
        right_panel.pack(side='left', fill='both', expand=True, padx=10, pady=10)

        # 聊天显示
        self.chat_display = scrolledtext.ScrolledText(
            right_panel,
            font=('Arial', 11),
            wrap=tk.WORD,
            state='disabled',
            relief=tk.FLAT,
            bd=1
        )
        self.chat_display.pack(fill='both', expand=True)

        # 输入区域
        input_frame = tk.Frame(right_panel)
        input_frame.pack(fill='x', pady=(10, 0))

        self.message_entry = tk.Entry(
            input_frame,
            font=('Arial', 11),
            relief=tk.FLAT,
            bd=2
        )
        self.message_entry.pack(side='left', fill='x', expand=True, ipady=5)
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        tk.Button(
            input_frame,
            text="发送 🔒",
            command=self.send_message,
            bg='#27ae60',
            fg='white',
            relief=tk.FLAT,
            padx=20,
            pady=8
        ).pack(side='left', padx=(10, 0))

        # 自动连接到服务器
        self.start_network()

    def refresh_trusted_peers(self):
        """刷新信任的对等节点列表"""
        self.trusted_peers_list.delete(0, tk.END)

        if self.trust_manager:
            for peer_id in self.trust_manager.trusted_peers.keys():
                self.trusted_peers_list.insert(tk.END, f"✓ {peer_id}")

    def on_peer_double_click(self, event):
        """双击对等节点"""
        selection = self.trusted_peers_list.curselection()
        if selection:
            peer_text = self.trusted_peers_list.get(selection[0])
            peer_id = peer_text.replace("✓ ", "")
            self.peer_entry.delete(0, tk.END)
            self.peer_entry.insert(0, peer_id)
            self.connect_to_peer()

    def connect_to_peer(self):
        """连接到对等节点"""
        peer_id = self.peer_entry.get().strip()

        if not peer_id:
            messagebox.showwarning("警告", "请输入对方用户名")
            return

        # 验证用户名
        try:
            peer_id = InputValidator.validate_username(peer_id)
        except ValidationError as e:
            messagebox.showerror("验证失败", str(e))
            return

        # 检查是否是自己
        if peer_id == self.username:
            messagebox.showerror("错误", "不能连接到自己")
            return

        # 模拟获取对方的密钥（实际应从服务器获取）
        peer_keys_dir = self.keys_dir / peer_id
        if not peer_keys_dir.exists():
            messagebox.showerror(
                "错误",
                f"对方用户 '{peer_id}' 不存在\n\n"
                f"请确保对方已注册。"
            )
            return

        try:
            # 加载对方的密钥存储
            peer_keystore = SecureKeyStore(peer_id, self.keys_dir)
            peer_keystore.load_certificate()

            # 只加载对方的公钥（无需密码）
            peer_keystore.load_public_keys_only()

            # 检查是否成功加载了所有必需的公钥
            if peer_keystore.dh_public_key is None or peer_keystore.verify_key is None:
                missing = []
                if peer_keystore.dh_public_key is None:
                    missing.append("DH公钥 (dh_public_key.pem)")
                if peer_keystore.verify_key is None:
                    missing.append("验证公钥 (verify_key.pem)")

                messagebox.showerror(
                    "密钥文件缺失",
                    f"对方用户 '{peer_id}' 缺少以下密钥文件：\n" +
                    "\n".join(f"  • {m}" for m in missing) +
                    f"\n\n这可能是旧版本创建的用户。\n\n" +
                    f"解决方法：\n" +
                    f"1. 让对方用户重新登录一次\n" +
                    f"2. 或运行迁移脚本：python3 migrate_add_dh_public_keys.py"
                )
                return

        except Exception as e:
            # 如果无法加载，请求输入
            messagebox.showerror(
                "错误",
                f"无法加载对方信息: {e}\n\n"
                f"在生产环境中，这些信息会从服务器获取。"
            )
            return

        # 验证对方证书
        if not self.ca.verify_certificate(peer_keystore.certificate):
            messagebox.showerror("错误", "对方证书验证失败")
            return

        # 获取证书指纹
        peer_fingerprint = self.ca.get_certificate_fingerprint(peer_keystore.certificate)

        # 检查是否已信任
        if not self.trust_manager.is_peer_trusted(peer_id, peer_fingerprint):
            # 显示指纹验证对话框
            result = messagebox.askyesno(
                "证书指纹验证",
                f"首次连接到 '{peer_id}'\n\n"
                f"证书指纹:\n{peer_fingerprint}\n\n"
                f"请通过其他安全渠道（电话、短信等）\n"
                f"与对方确认此指纹是否匹配。\n\n"
                f"⚠️ 如果指纹不匹配，可能存在中间人攻击！\n\n"
                f"指纹是否匹配？"
            )

            if not result:
                messagebox.showinfo("已取消", "连接已取消")
                return

            # 添加到信任列表
            self.trust_manager.add_trusted_peer(
                peer_id,
                peer_keystore.certificate,
                peer_fingerprint,
                verified_by_user=True
            )

            self.refresh_trusted_peers()

        # 执行密钥交换
        peer_keys = {
            'dh_key': peer_keystore.dh_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            'verify_key': peer_keystore.verify_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        }

        self.crypto.perform_key_exchange(
            peer_keys['dh_key'],
            peer_keys['verify_key']
        )

        self.current_peer = peer_id

        # 更新聊天显示
        self.display_system_message(
            f"✓ 已与 {peer_id} 建立安全连接\n"
            f"  - 端到端加密: AES-256-GCM\n"
            f"  - 证书已验证\n"
            f"  - 指纹: {peer_fingerprint[:16]}...\n"
        )

        # 加载历史消息
        if peer_id in self.chat_history:
            for msg in self.chat_history[peer_id]:
                self.display_message(msg['sender'], msg['content'], msg['time'])

        messagebox.showinfo(
            "连接成功",
            f"已与 {peer_id} 建立安全连接！\n\n"
            f"✓ 端到端加密已启用\n"
            f"✓ 证书已验证\n"
            f"✓ 所有消息将被加密"
        )

    def send_message(self):
        """发送消息"""
        if not self.current_peer:
            messagebox.showwarning("警告", "请先连接到对等节点")
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            # 验证消息
            message = InputValidator.validate_message(message)

            # 通过网络发送（如果已连接）
            if self.is_connected and self.ws:
                success = self.send_message_network(message)
                if not success:
                    return
            else:
                # 离线模式：只加密但不发送
                self.crypto.encrypt_message(message.encode())
                self.display_system_message("⚠️ 离线模式：消息未发送到网络")

            # 显示
            self.display_message(self.username, message, datetime.now())

            # 保存到历史
            if self.current_peer not in self.chat_history:
                self.chat_history[self.current_peer] = []

            self.chat_history[self.current_peer].append({
                'sender': self.username,
                'content': message,
                'time': datetime.now()
            })

            # 清空输入框
            self.message_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("发送失败", str(e))

    def display_message(self, sender, content, timestamp):
        """显示消息"""
        self.chat_display.config(state='normal')

        time_str = timestamp.strftime("%H:%M:%S")

        if sender == self.username:
            # 自己的消息（右对齐）
            self.chat_display.insert(tk.END, f"\n[{time_str}] 我:\n", 'time')
            self.chat_display.insert(tk.END, f"  {content}\n", 'me')
        else:
            # 对方的消息（左对齐）
            self.chat_display.insert(tk.END, f"\n[{time_str}] {sender}:\n", 'time')
            self.chat_display.insert(tk.END, f"  {content}\n", 'peer')

        self.chat_display.tag_config('time', foreground='gray')
        self.chat_display.tag_config('me', foreground='blue')
        self.chat_display.tag_config('peer', foreground='green')

        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def display_system_message(self, message):
        """显示系统消息"""
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"\n{message}\n", 'system')
        self.chat_display.tag_config('system', foreground='orange')
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def get_password_dialog(self, title):
        """密码输入对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()

        result = {'password': None}

        tk.Label(
            dialog,
            text=title,
            font=('Arial', 12, 'bold')
        ).pack(pady=20)

        tk.Label(
            dialog,
            text="密码:",
            font=('Arial', 10)
        ).pack(anchor='w', padx=40)

        password_entry = tk.Entry(dialog, show='*', font=('Arial', 11), width=30)
        password_entry.pack(pady=5, padx=40)

        if "设置" in title:
            tk.Label(
                dialog,
                text="确认密码:",
                font=('Arial', 10)
            ).pack(anchor='w', padx=40, pady=(10, 0))

            confirm_entry = tk.Entry(dialog, show='*', font=('Arial', 11), width=30)
            confirm_entry.pack(pady=5, padx=40)

            def on_submit():
                pwd = password_entry.get()
                confirm = confirm_entry.get()

                if pwd != confirm:
                    messagebox.showerror("错误", "两次密码不一致")
                    return

                # 验证密码强度
                policy = SecurityPolicy(SecurityLevel.MILITARY)
                valid, msg = policy.validate_password(pwd)

                if not valid:
                    messagebox.showerror("密码不符合要求", msg)
                    return

                result['password'] = pwd
                dialog.destroy()
        else:
            def on_submit():
                result['password'] = password_entry.get()
                dialog.destroy()

        tk.Button(
            dialog,
            text="确定",
            command=on_submit,
            bg='#3498db',
            fg='white',
            padx=20,
            pady=8
        ).pack(pady=20)

        password_entry.bind('<Return>', lambda e: on_submit())
        password_entry.focus()

        dialog.wait_window()
        return result['password']

    def logout(self):
        """注销"""
        if messagebox.askyesno("确认", "确定要注销吗？"):
            self.username = None
            self.keystore = None
            self.crypto = None
            self.current_peer = None
            self.show_login_screen()

    def clear_window(self):
        """清空窗口"""
        for widget in self.root.winfo_children():
            widget.destroy()

    # ==================== 网络通信功能 ====================

    def start_network(self):
        """启动网络连接"""
        if not self.async_thread or not self.async_thread.is_alive():
            self.async_thread = threading.Thread(target=self._run_async_loop, daemon=True)
            self.async_thread.start()
            time.sleep(0.5)  # 等待事件循环启动

    def _run_async_loop(self):
        """在后台线程运行异步事件循环"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect_to_server())

    async def _connect_to_server(self):
        """连接到信令服务器"""
        try:
            self.ws = await websockets.connect(SIGNALING_SERVER)

            # 注册到服务器
            await self.ws.send(json.dumps({
                'type': 'register',
                'client_id': self.username,
                'public_keys': {
                    'verify_key': self.keystore.verify_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ).hex(),
                    'dh_key': self.keystore.dh_public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    ).hex()
                }
            }))

            response = await self.ws.recv()
            data = json.loads(response)

            if data['type'] == 'registered':
                self.is_connected = True
                self.root.after(0, lambda: self.display_system_message("✓ 已连接到服务器"))
                print(f"✓ 已连接到服务器: {SIGNALING_SERVER}")

                # 开始处理消息
                await self._handle_server_messages()

        except Exception as e:
            print(f"连接服务器失败: {e}")
            self.root.after(0, lambda: messagebox.showerror("网络错误", f"无法连接到服务器\n{e}\n\n请确保信令服务器正在运行"))

    async def _handle_server_messages(self):
        """处理来自服务器的消息"""
        try:
            async for message in self.ws:
                data = json.loads(message)
                msg_type = data.get('type')

                if msg_type == 'relay_message':
                    # 收到对等节点的消息
                    peer_id = data['from']
                    encrypted_data = bytes.fromhex(data['data'])

                    # 解密消息
                    plaintext = self.crypto.decrypt_message(encrypted_data)
                    if plaintext:
                        content = plaintext.decode('utf-8')
                        # 在UI线程中更新界面
                        self.root.after(0, lambda p=peer_id, c=content: self._on_message_received(p, c))

                elif msg_type == 'peer_online':
                    peer_id = data['peer_id']
                    self.online_users[peer_id] = data.get('public_keys', {})
                    self.root.after(0, lambda: self.display_system_message(f"👤 {peer_id} 上线了"))

                elif msg_type == 'peer_offline':
                    peer_id = data['peer_id']
                    if peer_id in self.online_users:
                        del self.online_users[peer_id]
                    self.root.after(0, lambda: self.display_system_message(f"👤 {peer_id} 离线了"))

        except websockets.exceptions.ConnectionClosed:
            self.is_connected = False
            print("与服务器的连接已断开")
        except Exception as e:
            print(f"处理服务器消息时出错: {e}")

    def _on_message_received(self, peer_id, content):
        """收到消息的回调（在UI线程中执行）"""
        # 保存到历史
        if peer_id not in self.chat_history:
            self.chat_history[peer_id] = []

        self.chat_history[peer_id].append({
            'sender': peer_id,
            'content': content,
            'time': datetime.now()
        })

        # 如果正在和发送者聊天，显示消息
        if self.current_peer == peer_id:
            self.display_message(peer_id, content, datetime.now())

    def send_message_network(self, content):
        """通过网络发送消息"""
        if not self.is_connected or not self.ws:
            messagebox.showwarning("网络未连接", "请先连接到服务器")
            return False

        if not self.current_peer:
            messagebox.showwarning("未选择对话", "请先建立安全连接")
            return False

        try:
            # 加密消息
            encrypted = self.crypto.encrypt_message(content.encode())

            # 发送到服务器
            asyncio.run_coroutine_threadsafe(
                self.ws.send(json.dumps({
                    'type': 'relay',
                    'from': self.username,
                    'to': self.current_peer,
                    'data': encrypted.hex()
                })),
                self.loop
            )

            return True

        except Exception as e:
            print(f"发送消息失败: {e}")
            messagebox.showerror("发送失败", str(e))
            return False

    def on_closing(self):
        """关闭窗口时的清理"""
        if self.ws:
            try:
                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)
            except:
                pass

        self.root.destroy()


def main():
    """主函数"""
    try:
        # 导入serialization
        from cryptography.hazmat.primitives import serialization
        globals()['serialization'] = serialization

        root = tk.Tk()
        app = SecureChatClient(root)
        root.mainloop()

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
