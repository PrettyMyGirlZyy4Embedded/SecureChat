#!/bin/bash
# 安全聊天客户端启动脚本
# 自动清除缓存并启动应用

echo "========================================"
echo "  SecureChat - 军事级安全聊天"
echo "========================================"
echo ""

# 清除缓存
echo "清除 Python 缓存..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
echo "✓ 缓存已清除"
echo ""

# 检查依赖
echo "检查依赖..."
python3 -c "import tkinter; import cryptography; from Crypto.Cipher import AES" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  缺少依赖，尝试安装..."
    pip3 install cryptography pycryptodome qrcode pillow -q
fi
echo "✓ 依赖检查完成"
echo ""

# 启动应用
echo "启动 SecureChat..."
echo ""
python3 -B test.py

echo ""
echo "SecureChat 已退出"
