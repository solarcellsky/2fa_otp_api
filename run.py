# 启动脚本
# 用于启动2FA+TOTP认证API服务

import uvicorn
import os
import sys
from dotenv import load_dotenv
import http.server
import socketserver

# 加载环境变量
load_dotenv()

# 设置默认环境变量
if not os.getenv("DATABASE_URL"):
    os.environ[
        "DATABASE_URL"] = "postgresql://postgres:super666@127.0.0.1:15433/totp_auth"
if not os.getenv("SECRET_KEY"):
    os.environ["SECRET_KEY"] = "A8yBOXluTnSqv+o48LWq2QSKcoxSnM9aRUy/Tg+r+6o="
if not os.getenv("ENCRYPTION_KEY"):
    os.environ[
        "ENCRYPTION_KEY"] = "/51PJtNMA4znUU9Aegrhgch2BKgY6Xz0UQ+RuafN7J0="


# 启动服务
def run_api():
    print("正在启动2FA+TOTP认证API服务...")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)


def run_web():
    web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    os.chdir(web_dir)
    port = 8081
    handler = http.server.SimpleHTTPRequestHandler
    print(f"Serving web/ at http://127.0.0.1:{port}")
    with socketserver.TCPServer(("", port), handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "web":
        run_web()
    else:
        run_api()
