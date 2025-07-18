# 📦 local_file_sharing_tool

🚀 一个基于 Flask 的局域网文件上传与下载服务平台，支持管理员和用户登录，提供用户管理、密码修改、文件隔离与公共文件共享和私有文件分发和集中等功能，适用于学校、单位、办公室和家庭等本地网络环境，数据不出网，安全高效。

![Stars](https://img.shields.io/github/stars/hnbc2022/flask_file_server)
![Forks](https://img.shields.io/github/forks/hnbc2022/flask_file_server)
![License](https://img.shields.io/github/license/hnbc2022/flask_file_server)

---

## ✨ 项目亮点

- 🔐 支持用户登录，权限分为“管理员”和“普通用户”  
- 🧑‍💼 管理员可单独添加用户，或通过点名册批量导入  
- 🔧 用户和管理员均可修改自己的登录密码  
- 📤 支持文件上传、下载与删除，以及共享文件夹双击浏览，前进和后退浏览 
- 📁 自动分配用户专属文件目录，确保数据隔离  
- 🌐 局域网部署，无需外网连接，保障数据安全  
- 🖥️ 提供 Windows 版本打包文件（`.exe`），开箱即用  
- 🚪 启动 `file_server.exe` 后，所有用户只需通过浏览器访问服务器 IP 和端口，无需安装任何客户端软件  

---

## 👥 账号说明

- **管理员账号**  
  用户名：admin  
  默认密码：ad1234  
  权限：可管理用户、设置公共共享目录、导入用户点名册，自动生成初始用户名和初始登录密码。

- **普通用户示例**  
  用户名：张三、李四 等  
  默认密码：password123  
  权限：访问公共目录、访问个人私有目录、上传文件、修改密码

> 支持上传 `点名册.xlsx` 批量添加用户信息。

---

## 🚀 快速开始（适合非技术用户）

### ✅ 使用已打包的 `.exe` 文件（推荐）

无需安装 Python、无需命令行，一键启动服务：

1. 前往 GitHub [Releases 页面](https://github.com/hnbc2022/flask_file_server/releases) 下载 `file_server.exe`
2.新建一个文件夹作为程序工作目录，将 file_server.exe 和 点名册.xlsx 拷贝（或拖入）该目录，以支持管理员批量管理用户。
2. 解压并双击运行 `file_server.exe`（首次运行请允许防火墙访问）
3. 浏览器中访问：

```
http://localhost:5000
```

或在局域网中访问：

```
http://你的IP地址:5000
```

---

## 🧰 开发者启动方式（可选）

### 1️⃣ 克隆仓库

```bash
git clone https://github.com/hnbc2022/flask_file_server.git
cd flask_file_server
```

### 2️⃣ 安装依赖（推荐 Conda）

```bash
conda env create -f my_flask_env.yml
conda activate my_flask_env
```

### 3️⃣ 启动开发服务

```bash
python file_server.py
```

---

## 📦 打包说明（生成 `.exe` 可执行文件）

项目已使用 PyInstaller 打包为 Windows 可执行文件。

如需自行打包，可使用以下命令（建议保存为 `build.bat`）：

```bat
conda activate my_flask_env
cd /d D:\flask_file_server

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

生成文件位于：`dist/file_server.exe`

---

## 📁 项目结构说明

```bash
flask_file_server/
├── file_server.py         # 主程序入口
├── file_server.exe        # 打包生成的可执行文件
├── templates/             # HTML 页面模板
├── static/                # 静态文件（CSS / JS / 图片等）
├── users.db               # 用户数据库（SQLite）
├── 点名册.xlsx            # 示例点名数据文件
├── server.log             # 服务运行日志
├── 安装说明.txt            # 环境与使用说明
├── 打包.txt                # 打包操作文档
├── my_flask_env.yml       # Conda 环境配置文件
```

---

## 🔧 功能开发中（TODO）

- [ ] 用户注册与权限分级
- [ ] 多文件批量上传支持
- [ ] 操作日志记录
- [ ] 文件搜索与筛选功能
- [ ] 自动压缩下载功能

欢迎提交 Issue 或 PR！

---

## 🎯 适用场景

✅ 学校教师分发/收取作业
✅ 公司内部文件共享中心
✅ 会议、培训文件分发与回收
✅ 家庭局域网数据同步与归档
✅ 其他局域网场合数据同步与归档

---

## 🤝 贡献指南

欢迎贡献以下内容：

- 🐞 Bug 提交 / 功能建议
- 🔧 提交 PR 进行代码优化
- 🖼️ 提供界面截图 / 演示文档

> 请确保代码格式清晰，注释合理，欢迎 Fork + Star！

---

## 🔒 注意事项

- 所有共享目录支持自定义设置
- 如需公网访问，可配合 [cpolar](https://www.cpolar.com/) 等工具实现内网穿透

---

## 📄 License

本项目采用 [MIT License](https://opensource.org/licenses/MIT) 开源协议，允许个人和商业免费使用。

---

## ⭐ 鼓励支持

如果这个项目对你有帮助：

- 欢迎点击右上角 ⭐ Star 支持作者
- 欢迎 Fork 🍴 修改分享
- 欢迎推广给老师、同事、同学，帮助更多人使用

---

📌 作者仓库地址：https://github.com/hnbc2022/flask_file_server
