import os
import threading
import time
from flask import Flask, render_template_string, send_from_directory, jsonify, request, redirect, url_for, session, \
    flash, send_file
import logging
import sys
import io
from tkinter import Tk, filedialog
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from functools import wraps
import psutil
import zipfile
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 确定 BASE_DIR
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# SQLite 数据库路径
DB_PATH = os.path.join(BASE_DIR, 'users.db')

# 路径定义
user_base_folder = os.path.abspath(os.path.join(BASE_DIR, 'privite_shared'))
base_shared_folder = os.path.abspath(os.path.join(BASE_DIR, 'common_shared'))
os.makedirs(base_shared_folder, exist_ok=True)
os.makedirs(user_base_folder, exist_ok=True)
folder_lock = threading.Lock()

# 文件和文件夹限制
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB 单文件
MAX_FOLDER_SIZE = 500 * 1024 * 1024  # 500MB 文件夹
MAX_FOLDER_DEPTH = 10  # 最大文件夹深度

# 配置日志
try:
    handlers = [logging.FileHandler(os.path.join(BASE_DIR, 'server.log'), encoding='utf-8')]
    if sys.stdout is not None:
        handlers.append(logging.StreamHandler(stream=io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')))
    else:
        logging.warning("No console available, logging to file only.")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
except PermissionError as e:
    print(f"无法写入日志文件 server.log: {str(e)}")
    sys.exit(1)

logger = logging.getLogger(__name__)


def terminate_existing_processes():
    """终止已运行的 file_server.py 或 file_server.exe 进程"""
    current_pid = os.getpid()
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.name() in ['python.exe', 'file_server.exe']:
                    cmdline = proc.cmdline()
                    if (proc.name() == 'python.exe' and len(cmdline) > 1 and 'file_server.py' in cmdline[-1]) or \
                            (proc.name() == 'file_server.exe'):
                        if proc.pid != current_pid:
                            logger.info(f"发现已运行的进程: PID {proc.pid}, 名称 {proc.name()}, 命令行 {cmdline}")
                            proc.terminate()
                            proc.wait(timeout=3)
                            logger.info(f"已终止进程: PID {proc.pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logger.error(f"终止进程失败: {e}")


def load_users():
    """从数据库加载用户数据到内存"""
    users = {}
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT username, password, role FROM users")
            for row in c.fetchall():
                users[row[0]] = {'password': row[1], 'role': row[2]}
            logger.info(f"从数据库加载 {len(users)} 个用户")
    except Exception as e:
        logger.error(f"加载用户失败: {e}")
        raise
    return users


def get_user_folder(username, role):
    """获取用户共享文件夹并确保其存在，清理特殊字符"""
    try:
        if role == 'admin':
            folder = base_shared_folder
            logger.info(f"管理员 {username} 使用文件夹: {folder}")
        else:
            clean_username = ''.join(c for c in username if c.isalnum() or ord(c) > 127)
            if not clean_username:
                clean_username = f"user_{hash(username) % 10000}"
            folder = os.path.join(user_base_folder, clean_username)
        folder = folder[:255]
        logger.debug(f"尝试创建文件夹: {folder} (原始用户名: {username})")
        os.makedirs(folder, exist_ok=True)
        if os.path.exists(folder) and os.path.isdir(folder):
            logger.info(f"成功创建/确认用户文件夹: {folder} (原始用户名: {username})")
        else:
            raise OSError(f"文件夹 {folder} 创建失败或不可访问")
        return folder
    except Exception as e:
        logger.error(f"创建用户 {username} 文件夹失败: {e}")
        raise


def init_db():
    """初始化 SQLite 数据库，仅在用户表不存在时创建并插入默认管理员"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.set_trace_callback(logger.debug)
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not c.fetchone():
                logger.info("用户表不存在，开始初始化")
                c.execute('''CREATE TABLE users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL
                )''')
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                          ('admin', generate_password_hash('ad1234'), 'admin'))
                logger.info("初始化数据库，插入 1 个用户（1 个管理员）")
            else:
                logger.info("用户表已存在，跳过初始化")
            conn.commit()
            with folder_lock:
                c.execute("SELECT username, role FROM users")
                for username, role in c.fetchall():
                    get_user_folder(username, role)
                logger.info("为现有用户创建共享文件夹完成")
    except Exception as e:
        logger.error(f"初始化数据库失败: {e}")
        raise


def init_users_from_excel():
    """从点名册.xlsx读取学生姓名并插入用户，同时创建共享文件夹"""
    try:
        excel_path = os.path.join(BASE_DIR, '点名册.xlsx')
        if not os.path.exists(excel_path):
            logger.error(f"点名册.xlsx 不存在于 {excel_path}")
            return False, f"点名册.xlsx 不存在于 {excel_path}"

        logger.info(f"找到点名册.xlsx，正在读取: {excel_path}")
        df = pd.read_excel(excel_path, sheet_name=0, header=0)
        logger.info(f"Excel 文件包含 {df.shape[0]} 行，{df.shape[1]} 列，列名: {df.columns.tolist()}")
        if df.shape[1] < 3:
            return False, "Excel 文件缺少第3列（姓名列）"

        student_names = df.iloc[:, 2].dropna().tolist()
        if not student_names:
            return False, "姓名列为空"

        initial_users = []
        seen_names = set(['admin'])
        for i, name in enumerate(student_names[1:], 1):
            name = str(name).strip()
            if not name:
                logger.warning("跳过空姓名")
                continue
            if name in seen_names:
                logger.warning(f"跳过重复用户名: {name}")
                continue
            initial_users.append((name, generate_password_hash('password123'), 'user'))
            seen_names.add(name)
            logger.info(f"添加学生用户: {name}")

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            try:
                c.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", initial_users)
                conn.commit()
                logger.info(
                    f"从点名册.xlsx 读取 {len(student_names)} 个学生姓名，实际添加 {len(initial_users)} 个学生用户")
            except sqlite3.IntegrityError as e:
                logger.error(f"插入用户失败，可能存在重复用户名: {e}")
                return False, f"插入用户失败: {e}"

            with folder_lock:
                for username, _, role in initial_users:
                    get_user_folder(username, role)
                logger.info("为所有用户创建共享文件夹完成")

        return True, f"成功添加 {len(initial_users)} 个学生用户"
    except Exception as e:
        logger.error(f"从点名册初始化用户失败: {e}")
        return False, f"初始化失败: {e}"


# 初始化数据库并加载用户
try:
    terminate_existing_processes()
    init_db()
    USERS = load_users()
except Exception as e:
    logger.error(f"启动失败: {e}")
    print(f"服务器启动失败: {e}")
    sys.exit(1)


# 检查登录状态的装饰器
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'username' not in session:
            flash('请先登录', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return wrap


# 检查管理员权限的装饰器
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'username' not in session or USERS.get(session['username'], {}).get('role') != 'admin':
            flash('需要管理员权限', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return wrap


# 简化的文件夹选择器（仅管理员）
def windows_folder_picker():
    result = []
    dialog_complete = threading.Event()

    def _picker_thread():
        try:
            import tkinter
            root = Tk()
            root.withdraw()
            selected_path = filedialog.askdirectory(title="请选择顶层共享文件夹")
            root.destroy()
            if selected_path:
                result.append(os.path.abspath(selected_path))
        except ImportError as e:
            result.append(('error', 'tkinter 未安装或不可用'))
        except Exception as e:
            result.append(('error', str(e)))
        finally:
            dialog_complete.set()

    try:
        t = threading.Thread(target=_picker_thread, daemon=True)
        t.start()
        dialog_complete.wait(timeout=30)
    except Exception as e:
        logger.error(f"文件夹选择器线程启动失败: {e}")
        return None

    if not dialog_complete.is_set():
        logger.warning("文件夹选择器超时")
        return None

    if result:
        if isinstance(result[0], tuple) and result[0][0] == 'error':
            raise RuntimeError(result[0][1])
        return result[0]
    return None


# 登录页面 HTML
LOGIN_HTML = '''
<!doctype html>
<html>
<head>
    <title>登录 - 文件共享服务</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .login-container {
            max-width: 400px;
            margin: 100px auto;
        }
        input[type="text"]#password {
            -webkit-text-security: disc;
            ime-mode: auto;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 class="text-center mb-4">登录</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post" action="/login" id="loginForm">
            <div class="mb-3">
                <label for="username" class="form-label">用户名</label>
                <input type="text" class="form-control" id="username" name="username" required autofocus>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">密码</label>
                <input type="text" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">登录</button>
        </form>
    </div>
    <script>
        document.getElementById('username').focus();
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const passwordInput = document.getElementById('password');
            passwordInput.value = passwordInput.value.trim().replace(/[\uFF00-\uFFFF]/g, function(char) {
                return String.fromCharCode(char.charCodeAt(0) - 0xFEE0);
            });
        });
    </script>
</body>
</html>
'''

# 用户管理页面 HTML（仅管理员）
USER_MANAGE_HTML = '''
<!doctype html>
<html>
<head>
    <title>用户管理 - 文件共享服务</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .container { max-width: 800px; }
        .user-table { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>👤 用户管理</h2>
            <div>
                <span class="me-3">欢迎，{{ session.username }}（管理员）！</span>
                <a href="/logout" class="btn btn-outline-danger btn-sm">注销</a>
                <a href="/" class="btn btn-outline-primary btn-sm">返回主页</a>
            </div>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>初始化用户</h5>
            </div>
            <div class="card-body">
                <button id="initUsersBtn" class="btn btn-primary">从点名册初始化用户</button>
                <div id="initStatus" class="alert" style="display: none;"></div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>添加新用户</h5>
            </div>
            <div class="card-body">
                <form id="addUserForm" method="post" action="/add_user">
                    <div class="mb-3">
                        <label for="new_username" class="form-label">用户名</label>
                        <input type="text" class="form-control" id="new_username" name="new_username" required>
                    </div>
                    <div class="mb-3">
                        <label for="new_password" class="form-label">密码</label>
                        <input type="text" class="form-control" id="new_password" name="new_password" required>
                    </div>
                    <div class="mb-3">
                        <label for="role" class="form-label">角色</label>
                        <select class="form-control" id="role" name="role">
                            <option value="user">普通用户</option>
                            <option value="admin">管理员</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-success">添加用户</button>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5>用户列表 ({{ user_count }} 项)</h5>
            </div>
            <div class="list-group list-group-flush user-table">
                {% for user, info in users.items() %}
                <div class="list-group-item d-flex justify-content-between align-items-center">
                    <span>{{ user }} ({{ '管理员' if info.role == 'admin' else '普通用户' }})</span>
                    <div>
                        <button class="btn btn-sm btn-outline-warning edit-user-btn me-2" data-username="{{ user }}">修改密码</button>
                        <button class="btn btn-sm btn-outline-danger delete-user-btn" data-username="{{ user }}">删除</button>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>

    <script>
        document.getElementById('initUsersBtn').addEventListener('click', function() {
            const btn = this;
            const statusDiv = document.getElementById('initStatus');
            btn.disabled = true;
            statusDiv.style.display = 'block';
            statusDiv.className = 'alert alert-info';
            statusDiv.textContent = '正在从点名册初始化用户...';

            const xhr = new XMLHttpRequest();
            xhr.timeout = 30000;

            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    btn.disabled = false;
                    try {
                        const result = JSON.parse(xhr.responseText);
                        if (xhr.status === 200 && result.success) {
                            statusDiv.className = 'alert alert-success';
                            statusDiv.textContent = result.message;
                            setTimeout(() => location.reload(), 800);
                        } else {
                            statusDiv.className = 'alert alert-danger';
                            statusDiv.textContent = '错误: ' + (result.message || '初始化失败');
                        }
                    } catch (e) {
                        statusDiv.className = 'alert alert-danger';
                        statusDiv.textContent = '错误: ' + (e.message || '未知错误');
                        console.error('初始化用户失败:', e);
                    }
                }
            };

            xhr.ontimeout = function() {
                statusDiv.className = 'alert alert-warning';
                statusDiv.textContent = '初始化用户超时，请重试';
                btn.disabled = false;
            };

            xhr.open('POST', '/init_users', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send();
        });

        document.getElementById('addUserForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const form = this;
            const submitBtn = form.querySelector('button[type="submit"]');
            submitBtn.disabled = true;

            const formData = new FormData(form);
            const xhr = new XMLHttpRequest();
            xhr.timeout = 30000;

            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    submitBtn.disabled = false;
                    try {
                        const result = JSON.parse(xhr.responseText);
                        if (xhr.status === 200 && result.success) {
                            alert('用户添加成功！');
                            location.reload();
                        } else {
                            alert('错误: ' + (result.message || '添加失败'));
                        }
                    } catch (e) {
                        alert('错误: ' + (e.message || '未知错误'));
                        console.error('添加用户失败:', e);
                    }
                }
            };

            xhr.ontimeout = function() {
                alert('添加用户超时，请重试');
                submitBtn.disabled = false;
            };

            xhr.open('POST', '/add_user', true);
            xhr.send(formData);
        });

        document.querySelectorAll('.edit-user-btn').forEach(button => {
            button.addEventListener('click', function() {
                const username = this.getAttribute('data-username');
                const newPassword = prompt(`请输入 ${username} 的新密码：`);
                if (!newPassword) return;

                const xhr = new XMLHttpRequest();
                xhr.timeout = 30000;

                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4) {
                        try {
                            const result = JSON.parse(xhr.responseText);
                            if (xhr.status === 200 && result.success) {
                                alert('密码修改成功！');
                                location.reload();
                            } else {
                                alert('错误: ' + (result.message || '修改失败'));
                            }
                        } catch (e) {
                            alert('错误: ' + (e.message || '未知错误'));
                            console.error('修改密码失败:', e);
                        }
                    }
                };

                xhr.ontimeout = function() {
                    alert('修改密码超时，请重试');
                };

                xhr.open('POST', '/edit_user', true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({ username: username, new_password: newPassword }));
            });
        });

        document.querySelectorAll('.delete-user-btn').forEach(button => {
            button.addEventListener('click', function() {
                const username = this.getAttribute('data-username');
                if (!confirm(`确定要删除用户 "${username}" 吗？此操作无法撤销！`)) return;

                const xhr = new XMLHttpRequest();
                xhr.timeout = 30000;

                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4) {
                        try {
                            const result = JSON.parse(xhr.responseText);
                            if (xhr.status === 200 && result.success) {
                                alert('用户删除成功！');
                                location.reload();
                            } else {
                                throw new Error(result.message || '删除失败');
                            }
                        } catch (e) {
                            alert('错误: ' + (e.message || '未知错误'));
                            console.error('删除用户失败:', e);
                        }
                    }
                };

                xhr.ontimeout = function() {
                    alert('删除用户超时，请重试');
                };

                xhr.open('POST', '/delete_user', true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({ username: username }));
            });
        });
    </script>
</body>
</html>
'''

# 密码修改页面 HTML（普通用户）
CHANGE_PASSWORD_HTML = '''
<!doctype html>
<html>
<head>
    <title>修改密码 - 文件共享服务</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .password-container {
            max-width: 400px;
            margin: 100px auto;
        }
    </style>
</head>
<body>
    <div class="password-container">
        <h2 class="text-center mb-4">修改密码</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form id="changePasswordForm" method="post" action="/change_password">
            <div class="mb-3">
                <label for="current_password" class="form-label">当前密码</label>
                <input type="text" class="form-control" id="current_password" name="current_password" required>
            </div>
            <div class="mb-3">
                <label for="new_password" class="form-label">新密码</label>
                <input type="text" class="form-control" id="new_password" name="new_password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">修改密码</button>
        </form>
        <a href="/" class="btn btn-outline-secondary w-100 mt-3">返回主页</a>
    </div>
    <script>
        document.getElementById('changePasswordForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const form = this;
            const submitBtn = form.querySelector('button[type="submit"]');
            submitBtn.disabled = true;

            const formData = new FormData(form);
            const xhr = new XMLHttpRequest();
            xhr.timeout = 30000;

            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    submitBtn.disabled = false;
                    try {
                        const result = JSON.parse(xhr.responseText);
                        if (xhr.status === 200 && result.success) {
                            alert('密码修改成功！');
                            window.location.href = '/';
                        } else {
                            alert('错误: ' + (result.message || '修改失败'));
                        }
                    } catch (e) {
                        alert('错误: ' + (e.message || '未知错误'));
                        console.error('修改密码失败:', e);
                    }
                }
            };

            xhr.ontimeout = function() {
                alert('修改密码超时，请重试');
                submitBtn.disabled = false;
            };

            xhr.open('POST', '/change_password', true);
            xhr.send(formData);
        });
    </script>
</body>
</html>
'''

# 主页面 HTML（支持文件夹浏览和下载）
MAIN_HTML = '''
<!doctype html>
<html>
<head>
    <title>文件共享服务</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        #folderBtn { transition: all 0.3s; }
        #dialogStatus, #uploadStatusPersonal, #uploadStatusPublic {
            display: none;
            margin-top: 15px;
        }
        #currentPathPersonal, #currentPathPublic {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            word-break: break-all;
        }
        .file-item { display: flex; align-items: center; cursor: pointer; }
        .file-icon { margin-right: 8px; }
        .file-name { flex-grow: 1; }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>🗂 Windows文件共享</h2>
            <div>
                <span class="me-3">欢迎，{{ session.username }}（{{ '管理员' if session.role == 'admin' else '用户' }}）！</span>
                {% if session.role == 'admin' %}
                <a href="/manage_users" class="btn btn-outline-info btn-sm me-2">用户管理</a>
                {% endif %}
                <a href="/change_password" class="btn btn-outline-warning btn-sm me-2">修改密码</a>
                <a href="/logout" class="btn btn-outline-danger btn-sm">注销</a>
            </div>
        </div>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% if session.role == 'admin' %}
        <div class="alert alert-info">
            <strong>当前共享路径：</strong>
            <code id="currentPathPublic">{{ public_path }}/<span id="subPathPublic"></span></code>
            <button id="backBtnPublic" class="btn btn-sm btn-outline-secondary ms-2" style="display: none;">返回上一级</button>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                文件夹选择
            </div>
            <div class="card-body text-center">
                <button id="folderBtn" class="btn btn-primary btn-lg">
                    🖿 选择顶层共享文件夹
                </button>
                <div id="dialogStatus" class="alert alert-info">
                    正在启动系统对话框...
                </div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>上传文件/文件夹（公共共享文件夹）</h5>
            </div>
            <div class="card-body">
                <form id="uploadFormPublic" method="post" enctype="multipart/form-data" action="/upload?folder=public">
                    <div class="input-group">
                        <input type="file" class="form-control" name="files" multiple webkitdirectory>
                        <button class="btn btn-success" type="submit">上传</button>
                    </div>
                </form>
                <div id="uploadStatusPublic" class="alert"></div>
            </div>
        </div>

        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5>公共共享文件夹文件列表 ({{ public_file_count }} 项)</h5>
            </div>
            <div class="list-group list-group-flush" id="publicFileList" data-folder="public">
                {% for item in public_files %}
                <div class="list-group-item file-item" data-path="{{ item.name }}" data-is-dir="{{ item.is_dir }}">
                    <span class="file-icon">{% if item.is_dir %}📁{% else %}📄{% endif %}</span>
                    <span class="file-name">{{ item.name }}</span>
                    <div>
                        {% if item.is_dir %}
                        <a href="/download_folder/{{ item.name }}?folder=public" class="btn btn-sm btn-outline-primary me-2">下载</a>
                        {% else %}
                        <a href="/download/{{ item.name }}?folder=public" class="btn btn-sm btn-outline-primary me-2">下载</a>
                        {% endif %}
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-filename="{{ item.name }}" data-folder="public">删除</button>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% else %}
        <div class="alert alert-info">
            <strong>个人共享路径：</strong>
            <code id="currentPathPersonal">{{ personal_path }}/<span id="subPathPersonal"></span></code>
            <button id="backBtnPersonal" class="btn btn-sm btn-outline-secondary ms-2" style="display: none;">返回上一级</button>
            <br>
            <strong>公共共享路径：</strong>
            <code id="currentPathPublic">{{ public_path }}/<span id="subPathPublic"></span></code>
            <button id="backBtnPublic" class="btn btn-sm btn-outline-secondary ms-2" style="display: none;">返回上一级</button>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>上传文件/文件夹（个人共享文件夹）</h5>
            </div>
            <div class="card-body">
                <form id="uploadFormPersonal" method="post" enctype="multipart/form-data" action="/upload?folder=personal">
                    <div class="input-group">
                        <input type="file" class="form-control" name="files" multiple webkitdirectory>
                        <button class="btn btn-success" type="submit">上传</button>
                    </div>
                </form>
                <div id="uploadStatusPersonal" class="alert"></div>
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>个人共享文件夹文件列表 ({{ personal_file_count }} 项)</h5>
            </div>
            <div class="list-group list-group-flush" id="personalFileList" data-folder="personal">
                {% for item in personal_files %}
                <div class="list-group-item file-item" data-path="{{ item.name }}" data-is-dir="{{ item.is_dir }}">
                    <span class="file-icon">{% if item.is_dir %}📁{% else %}📄{% endif %}</span>
                    <span class="file-name">{{ item.name }}</span>
                    <div>
                        {% if item.is_dir %}
                        <a href="/download_folder/{{ item.name }}?folder=personal" class="btn btn-sm btn-outline-primary me-2">下载</a>
                        {% else %}
                        <a href="/download/{{ item.name }}?folder=personal" class="btn btn-sm btn-outline-primary me-2">下载</a>
                        {% endif %}
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-filename="{{ item.name }}" data-folder="personal">删除</button>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5>上传文件/文件夹（公共共享文件夹）</h5>
            </div>
            <div class="card-body">
                <form id="uploadFormPublic" method="post" enctype="multipart/form-data" action="/upload?folder=public">
                    <div class="input-group">
                        <input type="file" class="form-control" name="files" multiple webkitdirectory>
                        <button class="btn btn-success" type="submit">上传</button>
                    </div>
                </form>
                <div id="uploadStatusPublic" class="alert"></div>
            </div>
        </div>

        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5>公共共享文件夹文件列表 ({{ public_file_count }} 项)</h5>
            </div>
            <div class="list-group list-group-flush" id="publicFileList" data-folder="public">
                {% for item in public_files %}
                <div class="list-group-item file-item" data-path="{{ item.name }}" data-is-dir="{{ item.is_dir }}">
                    <span class="file-icon">{% if item.is_dir %}📁{% else %}📄{% endif %}</span>
                    <span class="file-name">{{ item.name }}</span>
                    <div>
                        {% if item.is_dir %}
                        <a href="/download_folder/{{ item.name }}?folder=public" class="btn btn-sm btn-outline-primary me-2">下载</a>
                        {% else %}
                        <a href="/download/{{ item.name }}?folder=public" class="btn btn-sm btn-outline-primary me-2">下载</a>
                        {% endif %}
                        <button class="btn btn-sm btn-outline-danger delete-btn" data-filename="{{ item.name }}" data-folder="public">删除</button>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
    </div>

    <script>
    function loadFolder(folder, subPath) {
        const listContainer = document.getElementById(`${folder}FileList`);
        const subPathSpan = document.getElementById(`subPath${folder.charAt(0).toUpperCase() + folder.slice(1)}`);
        const backBtn = document.getElementById(`backBtn${folder.charAt(0).toUpperCase() + folder.slice(1)}`);
        const statusDiv = document.getElementById(`uploadStatus${folder.charAt(0).toUpperCase() + folder.slice(1)}`);
    
        console.log(`加载文件夹: folder=${folder}, subPath=${subPath}`); // 调试日志
    
        fetch(`/list_folder?path=${encodeURIComponent(subPath)}&folder=${folder}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP 错误: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    listContainer.innerHTML = ''; // 清空当前列表
                    data.items.forEach(item => {
                        const fullPath = subPath ? `${subPath}/${item.name}` : item.name;
                        const encodedFullPath = encodeURIComponent(fullPath);
                        const div = document.createElement('div');
                        div.className = 'list-group-item file-item';
                        div.dataset.path = fullPath;
                        div.dataset.isDir = item.is_dir.toString().toLowerCase();
                        div.innerHTML = `
                            <span class="file-icon">${item.is_dir ? '📁' : '📄'}</span>
                            <span class="file-name">${item.name}</span>
                            <div>
                                ${item.is_dir ?
                                    `<a href="/download_folder/${encodedFullPath}?folder=${folder}" class="btn btn-sm btn-outline-primary me-2">下载</a>` :
                                    `<a href="/download/${encodeURIComponent(item.name)}?folder=${folder}&path=${encodeURIComponent(subPath)}" class="btn btn-sm btn-outline-primary me-2">下载</a>`}
                                <button class="btn btn-sm btn-outline-danger delete-btn" data-filename="${item.name}" data-folder="${folder}" data-path="${encodedFullPath}">删除</button>
                            </div>
                        `;
                        listContainer.appendChild(div);
                        console.log(`添加项: name=${item.name}, isDir=${div.dataset.isDir}, fullPath=${fullPath}`);
                    });
                    subPathSpan.textContent = subPath || '';
                    backBtn.style.display = subPath ? 'inline-block' : 'none';
                    console.log(`文件夹加载成功: ${subPath}, 项数: ${data.items.length}`); // 修复：使用 subPath
                } else {
                    statusDiv.style.display = 'block';
                    statusDiv.className = 'alert alert-danger';
                    statusDiv.textContent = '错误: ' + (data.message || '无法加载文件夹');
                    console.error(`加载文件夹失败: ${data.message}`);
                }
            })
            .catch(error => {
                statusDiv.style.display = 'block';
                statusDiv.className = 'alert alert-danger';
                statusDiv.textContent = '错误: ' + (error.message || '无法加载文件夹');
                console.error('加载文件夹失败:', error);
            });
    }
    
    // 使用事件委托绑定双击事件
    function bindFolderEvents(folder) {
        const listContainer = document.getElementById(`${folder}FileList`);
        listContainer.addEventListener('dblclick', function(event) {
            event.preventDefault();
            const target = event.target.closest('.file-item');
            if (target && target.dataset.isDir === 'true') {
                const path = target.dataset.path;
                console.log(`双击文件夹: folder=${folder}, path=${path}, isDir=${target.dataset.isDir}`);
                loadFolder(folder, path);
            } else {
                console.log(`双击无效: target=${target ? target.outerHTML : 'null'}, isDir=${target ? target.dataset.isDir : 'null'}`);
            }
        });
    
        // 绑定删除事件
        listContainer.addEventListener('click', function(event) {
            const button = event.target.closest('.delete-btn');
            if (button) {
                const filename = button.getAttribute('data-filename');
                const folder = button.getAttribute('data-folder');
                const path = button.getAttribute('data-path');
                const confirmDelete = confirm(`确定要删除 "${filename}" 吗？此操作无法撤销！`);
    
                if (!confirmDelete) return;
    
                const xhr = new XMLHttpRequest();
                xhr.timeout = 30000;
    
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4) {
                        const statusDiv = document.getElementById(`uploadStatus${folder.charAt(0).toUpperCase() + folder.slice(1)}`);
                        try {
                            const result = JSON.parse(xhr.responseText);
                            if (xhr.status === 200 && result.success) {
                                statusDiv.style.display = 'block';
                                statusDiv.className = 'alert alert-success';
                                statusDiv.textContent = '删除成功，正在刷新...';
                                setTimeout(() => loadFolder(folder, document.getElementById(`subPath${folder.charAt(0).toUpperCase() + folder.slice(1)}`).textContent), 800);
                            } else {
                                throw new Error(result.message || '删除失败');
                            }
                        } catch (e) {
                            statusDiv.style.display = 'block';
                            statusDiv.className = 'alert alert-danger';
                            statusDiv.textContent = '错误: ' + (e.message || '未知错误');
                            console.error('删除失败:', e);
                        }
                    }
                };
    
                xhr.ontimeout = function() {
                    const statusDiv = document.getElementById(`uploadStatus${folder.charAt(0).toUpperCase() + folder.slice(1)}`);
                    statusDiv.style.display = 'block';
                    statusDiv.className = 'alert alert-warning';
                    statusDiv.textContent = '删除超时，请重试';
                };
    
                xhr.open('POST', `/delete/${encodeURIComponent(filename)}?folder=${folder}&path=${encodeURIComponent(path)}`, true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send();
            }
        });
    }
    
    // 抽取上传事件绑定函数
    function bindUploadEvents(formId, folder) {
        const form = document.getElementById(formId);
        const statusDiv = document.getElementById(`uploadStatus${folder.charAt(0).toUpperCase() + folder.slice(1)}`);
        const subPath = document.getElementById(`subPath${folder.charAt(0).toUpperCase() + folder.slice(1)}`).textContent;
    
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            const submitBtn = form.querySelector('button[type="submit"]');
            const fileInput = form.querySelector('input[type="file"]');
            submitBtn.disabled = true;
            statusDiv.style.display = 'block';
            statusDiv.className = 'alert alert-info';
            statusDiv.textContent = '正在上传文件/文件夹...';
    
            const formData = new FormData(form);
            const files = fileInput.files;
            if (files.length === 0) {
                statusDiv.className = 'alert alert-danger';
                statusDiv.textContent = '错误: 未选择任何文件或文件夹';
                submitBtn.disabled = false;
                return;
            }
    
            // 添加当前子路径到 formData
            formData.append('subPath', subPath);
    
            const xhr = new XMLHttpRequest();
            xhr.timeout = 120000;
    
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    submitBtn.disabled = false;
                    try {
                        const result = JSON.parse(xhr.responseText);
                        if (xhr.status === 200 && result.success) {
                            statusDiv.className = 'alert alert-success';
                            statusDiv.textContent = '上传成功，正在刷新...';
                            setTimeout(() => loadFolder(folder, subPath), 800); // 刷新当前目录
                        } else {
                            statusDiv.className = 'alert alert-danger';
                            statusDiv.textContent = '错误: ' + (result.message || '上传失败');
                            console.error('上传失败:', result.message);
                        }
                    } catch (e) {
                        statusDiv.className = 'alert alert-danger';
                        statusDiv.textContent = '错误: ' + (e.message || '未知错误');
                        console.error('上传失败:', e);
                    }
                }
            };
    
            xhr.ontimeout = function() {
                statusDiv.className = 'alert alert-warning';
                statusDiv.textContent = '上传超时，请重试';
                submitBtn.disabled = false;
            };
    
            xhr.open('POST', `/upload?folder=${folder}`, true);
            xhr.send(formData);
        });
    }
    
    // 初始化文件夹列表
    function initFolders() {
        {% if session.role == 'admin' %}
        loadFolder('public', '');
        bindFolderEvents('public');
        bindUploadEvents('uploadFormPublic', 'public');
        {% else %}
        loadFolder('personal', '');
        loadFolder('public', '');
        bindFolderEvents('personal');
        bindFolderEvents('public');
        bindUploadEvents('uploadFormPersonal', 'personal');
        bindUploadEvents('uploadFormPublic', 'public');
        {% endif %}
    }
    
    // 页面加载时初始化
    document.addEventListener('DOMContentLoaded', initFolders);
    
    // 绑定文件夹选择器和返回按钮事件
    {% if session.role == 'admin' %}
    document.getElementById('folderBtn').addEventListener('click', function() {
        const btn = this;
        const statusDiv = document.getElementById('dialogStatus');
    
        btn.disabled = true;
        statusDiv.style.display = 'block';
    
        const xhr = new XMLHttpRequest();
        xhr.timeout = 45000;
    
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                btn.disabled = false;
    
                try {
                    const result = JSON.parse(xhr.responseText);
                    if (xhr.status === 200 && result.success) {
                        statusDiv.className = 'alert alert-success';
                        statusDiv.textContent = '路径已更新，正在刷新...';
                        document.getElementById('currentPathPublic').textContent = result.path;
                        setTimeout(() => location.reload(), 800);
                    } else {
                        throw new Error(result.message || '操作失败');
                    }
                } catch (e) {
                    statusDiv.className = 'alert alert-danger';
                    statusDiv.textContent = '错误: ' + (e.message || '未知错误');
                    console.error('请求失败:', e);
                }
            }
        };
    
        xhr.ontimeout = function() {
            statusDiv.className = 'alert alert-warning';
            statusDiv.textContent = '操作超时，请重试';
        };
    
        xhr.open('POST', '/pick_folder', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send();
    });
    
    document.getElementById('backBtnPublic').addEventListener('click', function() {
        const subPath = document.getElementById('subPathPublic').textContent;
        const parentPath = subPath.substring(0, subPath.lastIndexOf('/')) || '';
        console.log(`返回上一级: folder=public, parentPath=${parentPath}`);
        loadFolder('public', parentPath);
    });
    {% else %}
    document.getElementById('backBtnPersonal').addEventListener('click', function() {
        const subPath = document.getElementById('subPathPersonal').textContent;
        const parentPath = subPath.substring(0, subPath.lastIndexOf('/')) || '';
        console.log(`返回上一级: folder=personal, parentPath=${parentPath}`);
        loadFolder('personal', parentPath);
    });
    
    document.getElementById('backBtnPublic').addEventListener('click', function() {
        const subPath = document.getElementById('subPathPublic').textContent;
        const parentPath = subPath.substring(0, subPath.lastIndexOf('/')) || '';
        console.log(`返回上一级: folder=public, parentPath=${parentPath}`);
        loadFolder('public', parentPath);
    });
    {% endif %}
    </script>
</body>
</html>
'''


@app.route('/')
@login_required
def index():
    try:
        class FileItem:
            def __init__(self, name, is_dir):
                self.name = name
                self.is_dir = is_dir

        def list_files_with_dirs(folder_path):
            items = []
            for entry in os.listdir(folder_path):
                path = os.path.join(folder_path, entry)
                items.append(FileItem(entry, os.path.isdir(path)))
            return sorted(items, key=lambda x: (not x.is_dir, x.name.lower()))

        if session['role'] == 'admin':
            public_path = base_shared_folder
            public_files = list_files_with_dirs(public_path)
            return render_template_string(MAIN_HTML,
                                          public_path=public_path,
                                          public_files=public_files,
                                          public_file_count=len(public_files))
        else:
            personal_path = get_user_folder(session['username'], session['role'])
            public_path = base_shared_folder
            personal_files = list_files_with_dirs(personal_path)
            public_files = list_files_with_dirs(public_path)
            return render_template_string(MAIN_HTML,
                                          personal_path=personal_path,
                                          public_path=public_path,
                                          personal_files=personal_files,
                                          public_files=public_files,
                                          personal_file_count=len(personal_files),
                                          public_file_count=len(public_files))
    except Exception as e:
        logger.error(f"加载文件列表失败: {e}")
        flash(f"无法加载文件列表: {e}", 'danger')
        return render_template_string(MAIN_HTML, public_path=base_shared_folder, public_files=[], public_file_count=0)


@app.route('/list_folder')
@login_required
def list_folder():
    try:
        folder = request.args.get('folder', 'public')
        sub_path = request.args.get('path', '')
        if session['role'] == 'admin':
            current_shared_folder = base_shared_folder
        else:
            current_shared_folder = get_user_folder(session['username'],
                                                    session['role']) if folder == 'personal' else base_shared_folder

        full_path = os.path.join(current_shared_folder, sub_path)
        full_path = os.path.normpath(full_path)

        # 安全检查
        if not full_path.startswith(current_shared_folder):
            logger.warning(f"用户 {session['username']} 尝试访问非法路径: {full_path}")
            return jsonify(success=False, message="无权访问"), 403

        # 检查文件夹深度
        relative_path = os.path.relpath(full_path, current_shared_folder)
        depth = len(relative_path.split(os.sep)) if relative_path != '.' else 0
        if depth > MAX_FOLDER_DEPTH:
            logger.warning(f"用户 {session['username']} 访问文件夹深度超过限制: {full_path}")
            return jsonify(success=False, message=f"文件夹深度超过 {MAX_FOLDER_DEPTH} 级"), 400

        if not os.path.isdir(full_path):
            logger.error(f"文件夹不存在: {full_path}")
            return jsonify(success=False, message="文件夹不存在"), 404

        items = []
        for entry in os.listdir(full_path):
            entry_path = os.path.join(full_path, entry)
            items.append({'name': entry, 'is_dir': os.path.isdir(entry_path)})
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

        logger.info(f"用户 {session['username']}（{session['role']}）浏览文件夹: {full_path}（{folder} 文件夹）")
        return jsonify(success=True, items=items)
    except Exception as e:
        logger.error(f"用户 {session['username']} 浏览文件夹失败: {e}")
        return jsonify(success=False, message=f"加载文件夹失败: {e}"), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if not user:
                logger.warning(f"登录失败：用户名 {username} 不存在")
                flash('用户名不存在', 'danger')
            elif not check_password_hash(user[0], password):
                logger.warning(f"登录失败：用户 {username} 密码错误")
                flash('密码错误', 'danger')
            else:
                session['username'] = username
                session['role'] = user[1]
                get_user_folder(username, user[1])
                logger.info(f"用户 {username}（{session['role']}）登录成功")
                flash('登录成功！', 'success')
                return redirect(url_for('index'))

    return render_template_string(LOGIN_HTML)


@app.route('/logout')
@login_required
def logout():
    username = session.pop('username', None)
    role = session.pop('role', None)
    logger.info(f"用户 {username}（{role}）注销")
    flash('已注销', 'success')
    return redirect(url_for('login'))


@app.route('/pick_folder', methods=['POST'])
@login_required
@admin_required
def pick_folder():
    try:
        start_time = time.time()
        logger.info("正在启动文件夹选择器...")

        with folder_lock:
            selected_path = windows_folder_picker()
            elapsed = time.time() - start_time
            logger.info(f"文件夹选择完成，耗时 {elapsed:.2f} 秒")

            if not selected_path:
                return jsonify(
                    success=False,
                    message="文件夹选择已取消或超时"
                )

            if not os.path.isdir(selected_path):
                return jsonify(
                    success=False,
                    message="无效的文件夹路径"
                )

            global base_shared_folder
            base_shared_folder = selected_path
            logger.info(f"管理员 {session['username']} 更改顶层共享文件夹为 {base_shared_folder}")
            return jsonify(
                success=True,
                path=base_shared_folder,
                message="文件夹切换成功"
            )
    except Exception as e:
        logger.error(f"文件夹选择错误: {e}")
        return jsonify(
            success=False,
            message=f"操作失败: {e}"
        ), 500


@app.route('/download/<filename>')
@login_required
def download(filename):
    try:
        folder = request.args.get('folder', 'public')
        sub_path = request.args.get('path', '')
        if session['role'] == 'admin':
            current_shared_folder = base_shared_folder
        else:
            current_shared_folder = get_user_folder(session['username'],
                                                    session['role']) if folder == 'personal' else base_shared_folder
        file_path = os.path.join(current_shared_folder, sub_path, filename)
        file_path = os.path.normpath(file_path)
        if not os.path.isfile(file_path):
            logger.error(f"下载文件失败: {file_path} 不是文件")
            flash('文件不存在或不是文件', 'danger')
            return redirect(url_for('index'))
        return send_from_directory(
            os.path.dirname(file_path),
            os.path.basename(file_path),
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    except FileNotFoundError:
        logger.error(f"下载文件失败: {filename} 不存在")
        flash('文件不存在', 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"下载文件错误: {e}")
        flash(f"下载失败: {e}", 'danger')
        return redirect(url_for('index'))


@app.route('/download_folder/<path:foldername>')
@login_required
def download_folder(foldername):
    try:
        folder = request.args.get('folder', 'public')
        if session['role'] == 'admin':
            current_shared_folder = base_shared_folder
        else:
            current_shared_folder = get_user_folder(session['username'],
                                                    session['role']) if folder == 'personal' else base_shared_folder

        folder_path = os.path.join(current_shared_folder, foldername)
        folder_path = os.path.normpath(folder_path)

        # 安全检查
        if not folder_path.startswith(current_shared_folder):
            logger.warning(f"用户 {session['username']} 尝试下载非法文件夹: {folder_path}")
            return jsonify(success=False, message="无权访问"), 403

        if not os.path.isdir(folder_path):
            logger.error(f"下载文件夹失败: {folder_path} 不存在")
            flash('文件夹不存在', 'danger')
            return redirect(url_for('index'))

        # 检查文件夹深度
        relative_path = os.path.relpath(folder_path, current_shared_folder)
        depth = len(relative_path.split(os.sep)) if relative_path != '.' else 0
        if depth > MAX_FOLDER_DEPTH:
            logger.warning(f"用户 {session['username']} 下载文件夹深度超过限制: {folder_path}")
            return jsonify(success=False, message=f"文件夹深度超过 {MAX_FOLDER_DEPTH} 级"), 400

        # 检查文件夹大小
        total_size = 0
        for root, _, files in os.walk(folder_path):
            for file in files:
                total_size += os.path.getsize(os.path.join(root, file))
            if total_size > MAX_FOLDER_SIZE:
                logger.warning(
                    f"用户 {session['username']} 下载文件夹过大: {folder_path}, 大小 {total_size / (1024 * 1024)}MB")
                return jsonify(success=False, message=f"文件夹大小超过 {MAX_FOLDER_SIZE / (1024 * 1024)}MB"), 400

        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(folder_path):
                rel_root = os.path.relpath(root, current_shared_folder)
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.join(rel_root, file)
                    zf.write(file_path, arcname)
        memory_file.seek(0)

        logger.info(f"用户 {session['username']}（{session['role']}）下载文件夹: {folder_path}（{folder} 文件夹）")
        return send_file(
            memory_file,
            as_attachment=True,
            download_name=f"{os.path.basename(foldername)}.zip",
            mimetype='application/zip'
        )
    except Exception as e:
        logger.error(f"用户 {session['username']} 下载文件夹失败: {e}")
        flash(f"下载失败: {e}", 'danger')
        return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    try:
        folder = request.args.get('folder', 'public')
        sub_path = request.form.get('subPath', '')  # 获取前端传递的子路径

        if 'files' not in request.files:
            logger.warning(f"用户 {session['username']} 上传失败: 未选择文件或文件夹")
            return jsonify(
                success=False,
                message="未选择任何文件或文件夹"
            ), 400

        files = request.files.getlist('files')
        if not files:
            logger.warning(f"用户 {session['username']} 上传失败: 文件列表为空")
            return jsonify(
                success=False,
                message="未选择任何文件或文件夹"
            ), 400

        if session['role'] == 'admin':
            current_shared_folder = base_shared_folder
        else:
            current_shared_folder = get_user_folder(session['username'],
                                                   session['role']) if folder == 'personal' else base_shared_folder

        # 构建目标目录
        target_dir = os.path.join(current_shared_folder, sub_path)
        target_dir = os.path.normpath(target_dir)

        # 安全检查
        if not target_dir.startswith(current_shared_folder):
            logger.warning(f"用户 {session['username']} 尝试上传到非法路径: {target_dir}")
            return jsonify(success=False, message="无权访问"), 403

        uploaded_files = []
        with folder_lock:
            for file in files:
                if not file.filename:
                    continue

                # 优先使用 webkitRelativePath
                relative_path = getattr(file, 'webkitRelativePath', file.filename)
                if not relative_path:
                    logger.warning(f"文件 {file.filename} 无有效路径，跳过")
                    continue

                # 检查文件大小
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > MAX_FILE_SIZE:
                    logger.warning(f"文件 {relative_path} 太大，超过 {MAX_FILE_SIZE / (1024 * 1024)}MB 限制")
                    return jsonify(
                        success=False,
                        message=f"文件 {relative_path} 太大，最大允许 {MAX_FILE_SIZE / (1024 * 1024)}MB"
                    ), 400

                # 检查文件夹深度
                depth = len(relative_path.split('/')) - 1
                if depth > MAX_FOLDER_DEPTH:
                    logger.warning(f"文件 {relative_path} 深度超过限制: {depth} 级")
                    return jsonify(
                        success=False,
                        message=f"文件夹深度超过 {MAX_FOLDER_DEPTH} 级"
                    ), 400

                # 构建完整文件路径
                file_path = os.path.join(target_dir, relative_path)
                file_path = os.path.normpath(file_path)

                # 确保父目录存在
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                # 处理文件名冲突
                base, ext = os.path.splitext(os.path.basename(file_path))
                counter = 1
                new_filename = os.path.basename(file_path)
                new_file_path = file_path
                while os.path.exists(new_file_path):
                    new_filename = f"{base}_{counter}{ext}"
                    new_file_path = os.path.join(os.path.dirname(file_path), new_filename)
                    counter += 1

                file.save(new_file_path)
                uploaded_files.append(new_filename)
                logger.info(f"用户 {session['username']}（{session['role']}）上传文件: {new_file_path}（{folder} 文件夹）")

        if not uploaded_files:
            logger.warning(f"用户 {session['username']} 上传失败: 没有有效文件被上传")
            return jsonify(
                success=False,
                message="没有有效文件被上传"
            ), 400

        return jsonify(
            success=True,
            message=f"成功上传 {len(uploaded_files)} 个文件"
        )
    except Exception as e:
        logger.error(f"用户 {session['username']}（{session['role']}）文件上传错误: {e}")
        return jsonify(
            success=False,
            message=f"上传失败: {str(e)}"
        ), 500


@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete(filename):
    try:
        folder = request.args.get('folder', 'public')
        sub_path = request.args.get('path', '')
        if session['role'] == 'admin':
            current_shared_folder = base_shared_folder
        else:
            current_shared_folder = get_user_folder(session['username'],
                                                    session['role']) if folder == 'personal' else base_shared_folder

        with folder_lock:
            file_path = os.path.join(current_shared_folder, sub_path, filename)
            file_path = os.path.normpath(file_path)

            if not file_path.startswith(current_shared_folder):
                logger.warning(f"用户 {session['username']} 尝试删除非法路径: {file_path}")
                return jsonify(success=False, message="无权访问"), 403

            if not os.path.exists(file_path):
                logger.error(f"删除失败: {file_path} 不存在")
                return jsonify(
                    success=False,
                    message="文件或文件夹不存在"
                ), 404

            if os.path.isdir(file_path):
                import shutil
                shutil.rmtree(file_path)
                logger.info(
                    f"用户 {session['username']}（{session['role']}）删除文件夹成功: {file_path}（{folder} 文件夹）")
            else:
                os.remove(file_path)
                logger.info(f"用户 {session['username']}（{session['role']}）删除文件成功: {file_path}（{folder} 文件夹）")

            return jsonify(
                success=True,
                message="删除成功"
            )
    except Exception as e:
        logger.error(f"用户 {session['username']}（{session['role']}）删除错误: {e}")
        return jsonify(
            success=False,
            message=f"删除失败: {e}"
        ), 500


@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    try:
        return render_template_string(USER_MANAGE_HTML,
                                      users=USERS,
                                      user_count=len(USERS))
    except Exception as e:
        logger.error(f"加载用户管理页面失败: {e}")
        flash(f"无法加载用户管理页面: {e}", 'danger')
        return redirect(url_for('index'))


@app.route('/init_users', methods=['POST'])
@login_required
@admin_required
def init_users():
    try:
        success, message = init_users_from_excel()
        if success:
            global USERS
            USERS = load_users()
            return jsonify(
                success=True,
                message=message
            )
        else:
            return jsonify(
                success=False,
                message=message
            ), 400
    except Exception as e:
        logger.error(f"管理员 {session['username']} 初始化用户错误: {e}")
        return jsonify(
            success=False,
            message=f"初始化用户失败: {e}"
        ), 500


@app.route('/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    try:
        new_username = request.form.get('new_username').strip()
        new_password = request.form.get('new_password').strip()
        role = request.form.get('role').strip()

        if not new_username or not new_password:
            return jsonify(
                success=False,
                message="用户名和密码不能为空"
            ), 400

        if role not in ['user', 'admin']:
            return jsonify(
                success=False,
                message="无效的角色"
            ), 400

        with folder_lock:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE username = ?", (new_username,))
                if c.fetchone():
                    return jsonify(
                        success=False,
                        message="用户名已存在"
                    ), 400

                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                          (new_username, generate_password_hash(new_password), role))
                conn.commit()
                USERS[new_username] = {'password': generate_password_hash(new_password), 'role': role}
                get_user_folder(new_username, role)
                logger.info(f"管理员 {session['username']} 添加用户 {new_username}（{role}）成功")
                return jsonify(
                    success=True,
                    message="用户添加成功"
                )
    except Exception as e:
        logger.error(f"添加用户错误: {e}")
        return jsonify(
            success=False,
            message=f"添加用户失败: {e}"
        ), 500


@app.route('/edit_user', methods=['POST'])
@login_required
@admin_required
def edit_user():
    try:
        data = request.get_json()
        username = data.get('username').strip()
        new_password = data.get('new_password').strip()

        if not username or not new_password:
            return jsonify(
                success=False,
                message="用户名和密码不能为空"
            ), 400

        with folder_lock:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE username = ?", (username,))
                if not c.fetchone():
                    return jsonify(
                        success=False,
                        message="用户不存在"
                    ), 404

                c.execute("UPDATE users SET password = ? WHERE username = ?",
                          (generate_password_hash(new_password), username))
                conn.commit()
                USERS[username]['password'] = generate_password_hash(new_password)
                logger.info(f"管理员 {session['username']} 修改用户 {username} 的密码成功")
                return jsonify(
                    success=True,
                    message="密码修改成功"
                )
    except Exception as e:
        logger.error(f"修改用户密码错误: {e}")
        return jsonify(
            success=False,
            message=f"修改密码失败: {e}"
        ), 500


@app.route('/delete_user', methods=['POST'])
@login_required
@admin_required
def delete_user():
    try:
        data = request.get_json()
        username = data.get('username').strip()

        if not username:
            return jsonify(
                success=False,
                message="用户名不能为空"
            ), 400

        if username == 'admin':
            return jsonify(
                success=False,
                message="不能删除默认管理员账号"
            ), 400

        with folder_lock:
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE username = ?", (username,))
                if not c.fetchone():
                    return jsonify(
                        success=False,
                        message="用户不存在"
                    ), 404

                c.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
                del USERS[username]
                logger.info(f"管理员 {session['username']} 删除用户 {username} 成功")
                return jsonify(
                    success=True,
                    message="用户删除成功"
                )
    except Exception as e:
        logger.error(f"删除用户错误: {e}")
        return jsonify(
            success=False,
            message=f"删除用户失败: {e}"
        ), 500


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'GET':
        return render_template_string(CHANGE_PASSWORD_HTML)

    try:
        current_password = request.form.get('current_password').strip()
        new_password = request.form.get('new_password').strip()

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username = ?", (session['username'],))
            stored_password = c.fetchone()[0]
            if not check_password_hash(stored_password, current_password):
                return jsonify(
                    success=False,
                    message="当前密码错误"
                ), 400

            with folder_lock:
                c.execute("UPDATE users SET password = ? WHERE username = ?",
                          (generate_password_hash(new_password), session['username']))
                conn.commit()
                USERS[session['username']]['password'] = generate_password_hash(new_password)
                logger.info(f"用户 {session['username']}（{session['role']}）修改密码成功")
                return jsonify(
                    success=True,
                    message="密码修改成功"
                )
    except Exception as e:
        logger.error(f"用户 {session['username']}（{session['role']}）修改密码错误: {e}")
        return jsonify(
            success=False,
            message=f"修改密码失败: {e}"
        ), 500

# 如果这个文件作为主程序运行，则启动 Flask 服务器
if __name__ == '__main__':
    try:
        # 启动 Flask 应用
        app.run(
            host='0.0.0.0',   # 监听所有可用 IP（支持局域网访问）
            port=7000,        # 设置服务端口为 7000
            threaded=True,    # 开启多线程处理请求，提高并发性能
            debug=False       # 关闭调试模式，生产环境推荐设为 False
        )
    except Exception as e:
        # 捕获启动过程中可能出现的异常，记录日志并退出程序
        logger.error(f"Flask 服务器启动失败: {e}")
        print(f"错误: {e}")
        sys.exit(1)  # 非正常退出程序
