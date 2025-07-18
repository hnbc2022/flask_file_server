import os
import threading
import time
from flask import Flask, render_template, send_from_directory, jsonify, request, redirect, url_for, session, \
    flash, Response
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
import tempfile
import urllib.parse

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10GB
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


MAX_FOLDER_DEPTH = 10  # 最大文件夹深度

# 配置日志
try:
    # 仅使用文件日志处理器
    handlers = [logging.FileHandler(os.path.join(BASE_DIR, 'server.log'), encoding='utf-8')]
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    logger = logging.getLogger(__name__)

    # 可选：为调试添加终端输出
    # if sys.stdout is not None and os.getenv('DEBUG', 'False').lower() == 'true':
    #     stream_handler = logging.StreamHandler(stream=io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8'))
    #     logger.addHandler(stream_handler)

except PermissionError as e:
    print(f"无法写入日志文件 server.log: {str(e)}")
    sys.exit(1)
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
            try:
                for entry in os.listdir(folder_path):
                    path = os.path.join(folder_path, entry)
                    is_dir = os.path.isdir(path) and not os.path.islink(path)  # 排除符号链接
                    logger.debug(f"检查路径: {path}, 是否为文件夹: {is_dir}, 是否为符号链接: {os.path.islink(path)}")
                    items.append(FileItem(entry, is_dir))
                return sorted(items, key=lambda x: (not x.is_dir, x.name.lower()))
            except Exception as e:
                logger.error(f"列出文件夹 {folder_path} 时出错: {e}")
                return []

        if session['role'] == 'admin':
            public_path = base_shared_folder
            public_files = list_files_with_dirs(public_path)
            return render_template('index.html',
                                  public_path=public_path,
                                  public_files=public_files,
                                  public_file_count=len(public_files))
        else:
            personal_path = get_user_folder(session['username'], session['role'])
            public_path = base_shared_folder
            personal_files = list_files_with_dirs(personal_path)
            public_files = list_files_with_dirs(public_path)
            return render_template('index.html',
                                  personal_path=personal_path,
                                  public_path=public_path,
                                  personal_files=personal_files,
                                  public_files=public_files,
                                  personal_file_count=len(personal_files),
                                  public_file_count=len(public_files))
    except Exception as e:
        logger.error(f"加载文件列表失败: {e}")
        flash(f"无法加载文件列表: {e}", 'danger')
        return render_template('index.html', public_path=base_shared_folder, public_files=[], public_file_count=0)

@app.route('/list_folder')
@login_required
def list_folder():
    try:
        folder = request.args.get('folder', 'public')
        sub_path = request.args.get('path', '').strip()
        if session['role'] == 'admin':
            current_shared_folder = base_shared_folder
        else:
            current_shared_folder = get_user_folder(session['username'],
                                                   session['role']) if folder == 'personal' else base_shared_folder

        # 处理空路径或上一级路径
        if not sub_path:
            full_path = current_shared_folder
        else:
            full_path = os.path.join(current_shared_folder, sub_path)
        full_path = os.path.normpath(full_path)

        # 安全检查：允许访问 current_shared_folder 的父目录
        real_full_path = os.path.realpath(full_path)
        real_current_shared_folder = os.path.realpath(current_shared_folder)
        parent_shared_folder = os.path.realpath(os.path.dirname(current_shared_folder))

        # 仅在非管理员访问个人文件夹或公共文件夹时限制访问父目录
        if not session['role'] == 'admin' and folder == 'personal':
            if not real_full_path.startswith(real_current_shared_folder):
                logger.warning(f"用户 {session['username']} 尝试访问非法路径: {real_full_path}")
                return jsonify(success=False, message="无权访问个人共享文件夹外的路径"), 403
        elif not real_full_path.startswith(parent_shared_folder):
            logger.warning(f"用户 {session['username']} 尝试访问非法路径: {real_full_path}")
            return jsonify(success=False, message="无权访问共享文件夹外的路径"), 403

        # 检查文件夹深度
        relative_path = os.path.relpath(real_full_path, real_current_shared_folder)
        depth = len(relative_path.split(os.sep)) if relative_path != '.' else 0
        if depth > MAX_FOLDER_DEPTH:
            logger.warning(f"用户 {session['username']} 访问文件夹深度超过限制: {real_full_path}")
            return jsonify(success=False, message=f"文件夹深度超过 {MAX_FOLDER_DEPTH} 级"), 400

        if not os.path.isdir(real_full_path):
            logger.error(f"文件夹不存在: {real_full_path}")
            return jsonify(success=False, message="文件夹不存在"), 404

        items = []
        for entry in os.listdir(real_full_path):
            entry_path = os.path.join(real_full_path, entry)
            is_dir = os.path.isdir(entry_path) and not os.path.islink(entry_path)
            size = 0
            if is_dir:
                for root, _, files in os.walk(entry_path):
                    for file in files:
                        try:
                            size += os.path.getsize(os.path.join(root, file))
                        except Exception as e:
                            logger.warning(f"无法获取文件 {os.path.join(root, file)} 大小: {e}")
            logger.debug(f"列出文件夹 {real_full_path}: 项 {entry}, 是否为文件夹: {is_dir}, 大小: {size / (1024 * 1024):.2f}MB")
            items.append({'name': entry, 'is_dir': is_dir, 'size': size})
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

        logger.info(f"用户 {session['username']}（{session['role']}）浏览文件夹: {real_full_path}（{folder} 文件夹）")
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

    return render_template('login.html')

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

        # 使用临时文件创建 ZIP，不压缩
        start_time = time.time()
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
            with zipfile.ZipFile(temp_file, 'w', zipfile.ZIP_STORED) as zf:
                total_size = 0
                for root, _, files in os.walk(folder_path):
                    rel_root = os.path.relpath(root, current_shared_folder)
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.join(rel_root, file)
                        zf.write(file_path, arcname)
                        total_size += os.path.getsize(file_path)
            temp_file_path = temp_file.name

        elapsed = time.time() - start_time
        logger.info(f"用户 {session['username']}（{session['role']}）打包文件夹: {folder_path}（{folder} 文件夹），大小 {total_size / (1024 * 1024):.2f}MB，耗时 {elapsed:.2f}秒")

        # 处理非 ASCII 文件名
        filename = os.path.basename(foldername)
        ascii_filename = filename.encode('ascii', errors='ignore').decode('ascii') or 'download'
        encoded_filename = urllib.parse.quote(f"{filename}.zip", safe='')
        content_disposition = (
            f'attachment; filename="{ascii_filename}.zip"; '
            f'filename*=UTF-8\'\'{encoded_filename}'
        )

        # 流式传输 ZIP 文件
        def generate():
            with open(temp_file_path, 'rb') as f:
                while chunk := f.read(8192):
                    yield chunk
            os.unlink(temp_file_path)  # 下载完成后删除临时文件

        response = Response(
            generate(),
            mimetype='application/zip',
            headers={
                'Content-Disposition': content_disposition,
                'Content-Length': os.path.getsize(temp_file_path)
            }
        )
        return response
    except Exception as e:
        logger.error(f"用户 {session['username']} 下载文件夹失败: {e}")
        flash(f"下载失败: {e}", 'danger')
        return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    try:
        folder = request.args.get('folder', 'public')
        sub_path = request.form.get('subPath', '')

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

        target_dir = os.path.join(current_shared_folder, sub_path)
        target_dir = os.path.normpath(target_dir)

        if not target_dir.startswith(current_shared_folder):
            logger.warning(f"用户 {session['username']} 尝试上传到非法路径: {target_dir}")
            return jsonify(success=False, message="无权访问"), 403

        uploaded_files = []
        with folder_lock:
            for file in files:
                if not file.filename:
                    continue

                relative_path = getattr(file, 'webkitRelativePath', file.filename)
                if not relative_path:
                    logger.warning(f"文件 {file.filename} 无有效路径，跳过")
                    continue

                depth = len(relative_path.split('/')) - 1
                if depth > MAX_FOLDER_DEPTH:
                    logger.warning(f"文件 {relative_path} 深度超过限制: {depth} 级")
                    return jsonify(
                        success=False,
                        message=f"文件夹深度超过 {MAX_FOLDER_DEPTH} 级"
                    ), 400

                file_path = os.path.join(target_dir, relative_path)
                file_path = os.path.normpath(file_path)

                os.makedirs(os.path.dirname(file_path), exist_ok=True)

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

        file_path = os.path.join(current_shared_folder, sub_path, filename)
        file_path = os.path.normpath(file_path)

        logger.debug(f"用户 {session['username']} 尝试删除: {file_path} (folder={folder}, sub_path={sub_path})")

        # 安全检查
        if not file_path.startswith(current_shared_folder):
            logger.warning(f"用户 {session['username']} 尝试删除非法路径: {file_path}")
            return jsonify(success=False, message="无权访问"), 403

        if not os.path.exists(file_path):
            logger.error(f"删除失败: {file_path} 不存在")
            return jsonify(success=False, message="文件或文件夹不存在"), 404

        with folder_lock:
            start_time = time.time()
            if os.path.isdir(file_path):
                import shutil
                shutil.rmtree(file_path)
                elapsed = time.time() - start_time
                logger.info(
                    f"用户 {session['username']}（{session['role']}）删除文件夹成功: {file_path}（{folder} 文件夹），耗时 {elapsed:.2f}秒")
            else:
                os.remove(file_path)
                elapsed = time.time() - start_time
                logger.info(
                    f"用户 {session['username']}（{session['role']}）删除文件成功: {file_path}（{folder} 文件夹），耗时 {elapsed:.2f}秒")

        return jsonify(success=True, message="删除成功")
    except FileNotFoundError:
        logger.error(f"删除失败: {file_path} 不存在")
        return jsonify(success=False, message="文件或文件夹不存在"), 404
    except PermissionError:
        logger.error(f"删除失败: 用户 {session['username']} 无权限删除 {file_path}")
        return jsonify(success=False, message="无权限删除文件或文件夹"), 403
    except Exception as e:
        logger.error(f"用户 {session['username']} 删除错误: {e}")
        return jsonify(success=False, message=f"删除失败: {str(e)}"), 500

@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    try:
        return render_template('user_manage.html',
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
        return render_template('change_password.html')

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

if __name__ == '__main__':
    try:
        app.run(
            host='0.0.0.0',
            port=7000,
            threaded=True,
            debug=False
        )
    except Exception as e:
        logger.error(f"Flask 服务器启动失败: {e}")
        print(f"错误: {e}")
        sys.exit(1)