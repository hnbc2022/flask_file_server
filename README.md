# 📦 Flask 文件服务项目

这是一个基于 Flask 开发的本地文件上传与下载服务，适用于局域网访问或部署在服务器上。支持文件共享、上传下载、打包发布等功能。

---

## 🧰 项目结构

```
flask_file_server/
├── file_server.py         # 主程序，Flask 启动入口
├── file_server.exe        # 打包后的可执行文件（PyInstaller 生成）
├── users.db               # 用户数据（SQLite 数据库）
├── server.log             # 运行日志
├── common_shared/         # 公共共享目录
├── privite_shared/        # 私人文件目录
├── shared_folders/        # 其他共享目录
├── 点名.xlsx               # 示例数据文件
├── 安装说明.txt            # 安装环境说明
├── 打包.txt                # 打包流程说明（使用 PyInstaller）
├── .gitignore             # Git 忽略规则
├── my_flask_env.yml       # Conda 环境依赖文件
```

---

## 🛠️ 使用方法

### 1️⃣ 安装环境（推荐使用 Conda）

```bash
conda env create -f my_flask_env.yml
conda activate my_flask_env
```

### 2️⃣ 启动程序

```bash
python file_server.py
```

程序将启动在 `http://localhost:7000`，可通过浏览器访问文件服务。

---

## 🔧 打包说明（生成 `.exe` 可执行文件）

你可以使用以下命令将项目打包为单一的 `file_server.exe` 文件：

### 📌 打包环境要求：

- 已安装 PyInstaller
- 已激活 Conda 环境：`my_flask_env`

### 📁 打包命令（推荐保存为 `build.bat` 脚本）：

```bat
conda activate my_flask_env
cd /d D:lask_file_server

pyinstaller --onefile ^
  --noconsole ^
  --add-data "点名册.xlsx;." ^
  --add-data "users.db;." ^
  --collect-all flask ^
  --collect-all werkzeug ^
  --collect-all pandas ^
  --collect-all openpyxl ^
  --collect-all jinja2 ^
  --hidden-import tkinter ^
  --hidden-import tkinter.filedialog ^
  --log-level DEBUG ^
  file_server.py
```

打包成功后可在 `dist/file_server.exe` 找到生成文件。

---

## ✅ 注意事项

- 本地生成的 `users.db` 不建议推送到 GitHub
- 所有共享目录内容可自定义修改
- 如需公网访问，可结合 [cpolar](https://www.cpolar.com/) 等内网穿透工具使用

---

## 📄 License

本项目基于 [MIT License](https://opensource.org/licenses/MIT) 开源使用。
