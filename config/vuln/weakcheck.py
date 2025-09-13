import re
import socket
import requests
import time
import concurrent.futures
from colorama import Fore, Style
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 忽略SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 颜色输出函数
def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)


def print_red(text):
    print(Fore.RED + text + Style.RESET_ALL)


def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)


def print_yellow(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


def print_status(text):
    """打印检测状态信息（灰色）"""
    print(Fore.LIGHTBLACK_EX + text + Style.RESET_ALL)


class WeakPasswordChecker:
    def __init__(self, threads=10, dict_dir=None, verbose=False):
        self.threads = threads
        self.dict_dir = dict_dir if dict_dir else "config/vuln/weakcheck"
        self.verbose = verbose  # 控制是否显示详细状态

        # 所有检测模块映射表
        self.modules = {
            "ftp": self.check_ftp,
            "ssh": self.check_ssh,
            "telnet": self.check_telnet,
            "tomcat": self.check_tomcat,
            "mysql": self.check_mysql,
            "mongodb": self.check_mongodb,
            "rdp": self.check_rdp,
            "smb": self.check_smb,
            "vnc": self.check_vnc,
            "imap": self.check_imap,
            "pop3": self.check_pop3,
            "sqlserver": self.check_sqlserver,
            "weblogic": self.check_weblogic,
            "svn": self.check_svn,
            "redis": self.check_redis,
            "memcached": self.check_memcached,
            "elasticsearch": self.check_elasticsearch
        }

    # 从URL提取IP或域名转IP
    def extract_ip_from_url(self, url):
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc or parsed_url.path  # 处理无协议的URL
            # 移除端口
            host = host.split(':')[0]

            # 检查是否已为IP
            if self.is_valid_ip(host):
                return host

            # 域名转IP
            ip = socket.gethostbyname(host)
            return ip
        except Exception as e:
            print_red(f"[!] 解析IP失败: {str(e)}")
            return None

    # IP格式验证
    def is_valid_ip(self, ip):
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        if not match:
            return False
        for group in match.groups():
            if int(group) < 0 or int(group) > 255:
                return False
        return True

    # 生成IP列表（A/B/C段或单个IP）
    def generate_ip_list(self, base_ip, range_type):
        ip_list = []
        try:
            ip_parts = list(map(int, base_ip.split('.')))

            if range_type == 'single':
                ip_list = [base_ip]

            elif range_type == 'cidr':  # C段
                a, b, c, _ = ip_parts
                for d in range(1, 256):
                    ip_list.append(f"{a}.{b}.{c}.{d}")

            elif range_type == 'b_segment':  # B段
                a, b, _, _ = ip_parts
                for c in range(1, 256):
                    for d in range(1, 256):
                        ip_list.append(f"{a}.{b}.{c}.{d}")

            elif range_type == 'a_segment':  # A段
                a, _, _, _ = ip_parts
                for b in range(1, 256):
                    for c in range(1, 256):
                        for d in range(1, 256):
                            ip_list.append(f"{a}.{b}.{c}.{d}")

        except Exception as e:
            print_red(f"[!] 生成IP列表失败: {str(e)}")

        return ip_list

    # 加载字典文件
    def load_dict(self, filename):
        try:
            with open(f"{self.dict_dir}/{filename}", "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print_red(f"[!] 字典文件不存在: {self.dict_dir}/{filename}")
            return self.get_default_dict(filename)
        except Exception as e:
            print_red(f"[!] 加载字典失败: {str(e)}")
            return self.get_default_dict(filename)

    # 默认字典（当字典文件不存在时使用）
    def get_default_dict(self, filename):
        if 'username' in filename:
            return ['admin', 'root', 'user', 'test', 'administrator']
        elif 'password' in filename:
            return ['123456', 'password', 'admin', 'root', '12345678', '12345', '1234', '123', '']
        return []

    # 选择检测模块
    def select_modules(self):
        print_cyan("\n可用的弱密码检测模块：")
        modules_list = list(self.modules.items())
        for i, (name, _) in enumerate(modules_list, 1):
            print(f"{i}. {name}")
        print(f"{len(modules_list) + 1}. all (所有模块)")

        while True:
            choice = input("\n请输入模块编号（多个编号用逗号分隔）: ").strip()
            if not choice:
                print_red("请输入至少一个模块编号")
                continue

            selected = []
            for c in choice.split(','):
                c = c.strip()
                if not c.isdigit():
                    print_red(f"无效输入: {c}")
                    break
                idx = int(c) - 1
                if idx == len(modules_list):
                    # 选择所有模块
                    return list(self.modules.keys())
                if 0 <= idx < len(modules_list):
                    selected.append(modules_list[idx][0])
                else:
                    print_red(f"编号超出范围: {c}")
                    break
            else:
                if selected:
                    return list(set(selected))  # 去重
                print_red("未选择任何有效模块")

    # 执行扫描
    def run_scan(self, ip_list, selected_modules):
        total_tasks = len(ip_list) * len(selected_modules)
        completed_tasks = 0
        results = []

        print_cyan(
            f"\n[+] 开始弱密码扫描 | 目标IP数: {len(ip_list)} | 模块数: {len(selected_modules)} | 线程数: {self.threads} | 总任务数: {total_tasks}")

        # 多线程扫描
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for ip in ip_list:
                for module in selected_modules:
                    futures.append(executor.submit(
                        self.run_single_check,
                        ip,
                        module
                    ))

            # 处理结果
            for future in concurrent.futures.as_completed(futures):
                completed_tasks += 1
                # 显示扫描进度
                progress = (completed_tasks / total_tasks) * 100
                if completed_tasks % 10 == 0 or progress == 100:
                    print_status(f"[*] 扫描进度: {completed_tasks}/{total_tasks} ({progress:.1f}%)")

                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if "[+]" in result:  # 只打印存在弱密码的结果
                            print_red(result)
                        elif self.verbose and "[-]" in result:  # 详细模式下显示未发现结果
                            print_cyan(result)
                except Exception as e:
                    print_red(f"[!] 扫描出错: {str(e)}")

        return results

    # 执行单个检查
    def run_single_check(self, ip, module):
        print_status(f"[*] 开始检测 {ip} 的 {module} 服务")
        try:
            if module in self.modules:
                result = self.modules[module](ip)
                return result
            return f"{ip} 未知模块: {module}"
        except Exception as e:
            return f"{ip} {module} 检测出错: {str(e)}"

    # FTP弱密码检测
    def check_ftp(self, ip):
        try:
            import ftplib
            usernames = self.load_dict("dic_username_ftp.txt")
            passwords = self.load_dict("dic_password_ftp.txt")

            print_status(f"[*] {ip} FTP 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} FTP 尝试: {username}/{password}")
                    try:
                        ftp = ftplib.FTP()
                        ftp.connect(host=ip, port=21, timeout=5)
                        ftp.login(username, password)
                        ftp.quit()
                        return f"{ip}[+]FTP存在弱密码: {username}/{password}"
                    except ftplib.all_errors:
                        continue

            return f"{ip}[-]未发现FTP弱密码"
        except ImportError:
            return f"{ip}[!]缺少ftplib库，无法检测FTP"
        except Exception as e:
            return f"{ip}[!]FTP检测出错: {str(e)}"

    # SSH弱密码检测
    def check_ssh(self, ip):
        try:
            import paramiko
            usernames = self.load_dict("dic_username_ssh.txt")
            passwords = self.load_dict("dic_password_ssh.txt")

            print_status(f"[*] {ip} SSH 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} SSH 尝试: {username}/{password}")
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(hostname=ip, port=22, username=username, password=password, timeout=5)
                        ssh.close()
                        return f"{ip}[+]SSH存在弱密码: {username}/{password}"
                    except paramiko.AuthenticationException:
                        continue
                    except:
                        break

            return f"{ip}[-]未发现SSH弱密码"
        except ImportError:
            return f"{ip}[!]缺少paramiko库，无法检测SSH"
        except Exception as e:
            return f"{ip}[!]SSH检测出错: {str(e)}"

    # Telnet弱密码检测
    def check_telnet(self, ip):
        try:
            from telnetlib import Telnet
            usernames = self.load_dict("dic_username_telnet.txt")
            passwords = self.load_dict("dic_password_telnet.txt")

            print_status(f"[*] {ip} Telnet 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} Telnet 尝试: {username}/{password}")
                    try:
                        tn = Telnet(ip, timeout=5)
                        tn.read_until(b"login: ", timeout=3)
                        tn.write(username.encode('ascii') + b"\n")
                        tn.read_until(b"Password: ", timeout=3)
                        tn.write(password.encode('ascii') + b"\n")
                        # 尝试读取命令提示符判断是否登录成功
                        tn.read_until(b"$ " or b"# ", timeout=3)
                        tn.close()
                        return f"{ip}[+]Telnet存在弱密码: {username}/{password}"
                    except:
                        continue

            return f"{ip}[-]未发现Telnet弱密码"
        except Exception as e:
            return f"{ip}[!]Telnet检测出错: {str(e)}"

    # Tomcat弱密码检测
    def check_tomcat(self, ip):
        try:
            import base64
            usernames = self.load_dict("dic_username_tomcat.txt")
            passwords = self.load_dict("dic_password_tomcat.txt")

            print_status(f"[*] {ip} Tomcat 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            ports = [8080, 80, 443]
            for port in ports:
                url = f"http://{ip}:{port}/manager/html"
                for username in usernames:
                    for password in passwords:
                        print_status(f"[*] {ip}:{port} Tomcat 尝试: {username}/{password}")
                        try:
                            # 构建Basic认证
                            auth_str = f"{username}:{password}".encode()
                            auth_b64 = base64.b64encode(auth_str).decode()
                            headers = {"Authorization": f"Basic {auth_b64}"}

                            response = requests.get(url, headers=headers, timeout=5, verify=False)
                            if response.status_code == 200:
                                return f"{ip}:{port}[+]Tomcat存在弱密码: {username}/{password}"
                        except:
                            continue

            return f"{ip}[-]未发现Tomcat弱密码"
        except Exception as e:
            return f"{ip}[!]Tomcat检测出错: {str(e)}"

    # MySQL弱密码检测
    def check_mysql(self, ip):
        try:
            import pymysql
            usernames = self.load_dict("dic_username_mysql.txt")
            passwords = self.load_dict("dic_password_mysql.txt")

            print_status(f"[*] {ip} MySQL 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} MySQL 尝试: {username}/{password}")
                    try:
                        conn = pymysql.connect(
                            host=ip,
                            port=3306,
                            user=username,
                            passwd=password,
                            connect_timeout=5
                        )
                        conn.close()
                        return f"{ip}[+]MySQL存在弱密码: {username}/{password}"
                    except pymysql.err.OperationalError:
                        continue

            return f"{ip}[-]未发现MySQL弱密码"
        except ImportError:
            return f"{ip}[!]缺少pymysql库，无法检测MySQL"
        except Exception as e:
            return f"{ip}[!]MySQL检测出错: {str(e)}"

    # MongoDB弱密码检测
    def check_mongodb(self, ip):
        try:
            import pymongo
            usernames = self.load_dict("dic_username_mongodb.txt")
            passwords = self.load_dict("dic_password_mongodb.txt")

            print_status(f"[*] {ip} MongoDB 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} MongoDB 尝试: {username}/{password}")
                    try:
                        conn = pymongo.MongoClient(
                            ip,
                            username=username,
                            password=password,
                            serverSelectionTimeoutMS=5000
                        )
                        # 尝试获取数据库列表验证权限
                        conn.list_database_names()
                        return f"{ip}[+]MongoDB存在弱密码: {username}/{password}"
                    except:
                        continue

            return f"{ip}[-]未发现MongoDB弱密码"
        except ImportError:
            return f"{ip}[!]缺少pymongo库，无法检测MongoDB"
        except Exception as e:
            return f"{ip}[!]MongoDB检测出错: {str(e)}"

    # RDP弱密码检测
    def check_rdp(self, ip):
        try:
            usernames = self.load_dict("dic_username_rdp.txt")
            passwords = self.load_dict("dic_password_rdp.txt")

            print_status(f"[*] {ip} RDP 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            # RDP弱密码检测提示
            return f"{ip}[!]RDP弱密码检测建议使用专用工具（如hydra）"
        except Exception as e:
            return f"{ip}[!]RDP检测出错: {str(e)}"

    # SMB弱密码检测
    def check_smb(self, ip):
        try:
            from smb.SMBConnection import SMBConnection
            usernames = self.load_dict("dic_username_smb.txt")
            passwords = self.load_dict("dic_password_smb.txt")

            print_status(f"[*] {ip} SMB 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} SMB 尝试: {username}/{password}")
                    try:
                        conn = SMBConnection(
                            username,
                            password,
                            'client',
                            ip,
                            use_ntlm_v2=True
                        )
                        if conn.connect(ip, 139, timeout=5):
                            conn.close()
                            return f"{ip}[+]SMB存在弱密码: {username}/{password}"
                    except:
                        continue

            return f"{ip}[-]未发现SMB弱密码"
        except ImportError:
            return f"{ip}[!]缺少smb库，无法检测SMB"
        except Exception as e:
            return f"{ip}[!]SMB检测出错: {str(e)}"

    # VNC弱密码检测
    def check_vnc(self, ip):
        try:
            usernames = self.load_dict("dic_username_vnc.txt")
            passwords = self.load_dict("dic_password_vnc.txt")

            print_status(f"[*] {ip} VNC 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} VNC 尝试: {username}/{password}")
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((ip, 5900))
                        # 发送VNC协议握手信息
                        sock.sendall(b'RFB 003.008\n')
                        sock.recv(1024)
                        # 尝试发送密码
                        sock.sendall(b'\x01' + password.encode() + b'\n')
                        response = sock.recv(1024)
                        sock.close()

                        if b'OK' in response:
                            return f"{ip}[+]VNC存在弱密码: {username}/{password}"
                    except:
                        continue

            return f"{ip}[-]未发现VNC弱密码"
        except Exception as e:
            return f"{ip}[!]VNC检测出错: {str(e)}"

    # IMAP弱密码检测
    def check_imap(self, ip):
        try:
            import imaplib
            usernames = self.load_dict("dic_username_imap.txt")
            passwords = self.load_dict("dic_password_imap.txt")

            print_status(f"[*] {ip} IMAP 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            ports = [143, 993]
            for port in ports:
                for username in usernames:
                    for password in passwords:
                        print_status(f"[*] {ip}:{port} IMAP 尝试: {username}/{password}")
                        try:
                            if port == 993:
                                conn = imaplib.IMAP4_SSL(ip, port, timeout=5)
                            else:
                                conn = imaplib.IMAP4(ip, port, timeout=5)
                            conn.login(username, password)
                            conn.logout()
                            return f"{ip}:{port}[+]IMAP存在弱密码: {username}/{password}"
                        except imaplib.IMAP4.error:
                            continue
                        except:
                            break

            return f"{ip}[-]未发现IMAP弱密码"
        except Exception as e:
            return f"{ip}[!]IMAP检测出错: {str(e)}"

    # POP3弱密码检测
    def check_pop3(self, ip):
        try:
            import poplib
            usernames = self.load_dict("dic_username_pop3.txt")
            passwords = self.load_dict("dic_password_pop3.txt")

            print_status(f"[*] {ip} POP3 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            ports = [110, 995]
            for port in ports:
                for username in usernames:
                    for password in passwords:
                        print_status(f"[*] {ip}:{port} POP3 尝试: {username}/{password}")
                        try:
                            if port == 995:
                                conn = poplib.POP3_SSL(ip, port, timeout=5)
                            else:
                                conn = poplib.POP3(ip, port, timeout=5)
                            conn.user(username)
                            conn.pass_(password)
                            conn.quit()
                            return f"{ip}:{port}[+]POP3存在弱密码: {username}/{password}"
                        except poplib.error_proto:
                            continue
                        except:
                            break

            return f"{ip}[-]未发现POP3弱密码"
        except Exception as e:
            return f"{ip}[!]POP3检测出错: {str(e)}"

    # SQL Server弱密码检测
    def check_sqlserver(self, ip):
        try:
            import pyodbc
            usernames = self.load_dict("dic_username_sqlserver.txt")
            passwords = self.load_dict("dic_password_sqlserver.txt")

            print_status(f"[*] {ip} SQL Server 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} SQL Server 尝试: {username}/{password}")
                    try:
                        conn_str = f"Driver={{SQL Server}};Server={ip};UID={username};PWD={password};"
                        conn = pyodbc.connect(conn_str, timeout=5)
                        conn.close()
                        return f"{ip}[+]SQL Server存在弱密码: {username}/{password}"
                    except:
                        continue

            return f"{ip}[-]未发现SQL Server弱密码"
        except ImportError:
            return f"{ip}[!]缺少pyodbc库，无法检测SQL Server"
        except Exception as e:
            return f"{ip}[!]SQL Server检测出错: {str(e)}"

    # WebLogic弱密码检测
    def check_weblogic(self, ip):
        try:
            usernames = self.load_dict("dic_username_weblogic.txt")
            passwords = self.load_dict("dic_password_weblogic.txt")

            print_status(f"[*] {ip} WebLogic 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            ports = [7001, 7002]
            for port in ports:
                url = f"http://{ip}:{port}/console/j_security_check"
                for username in usernames:
                    for password in passwords:
                        print_status(f"[*] {ip}:{port} WebLogic 尝试: {username}/{password}")
                        try:
                            data = {
                                'j_username': username,
                                'j_password': password
                            }
                            response = requests.post(url, data=data, timeout=5, allow_redirects=False)
                            # 登录成功会重定向
                            if response.status_code == 302:
                                return f"{ip}:{port}[+]WebLogic存在弱密码: {username}/{password}"
                        except:
                            continue

            return f"{ip}[-]未发现WebLogic弱密码"
        except Exception as e:
            return f"{ip}[!]WebLogic检测出错: {str(e)}"

    # SVN弱密码检测
    def check_svn(self, ip):
        try:
            from svn.remote import RemoteClient
            usernames = self.load_dict("dic_username_svn.txt")
            passwords = self.load_dict("dic_password_svn.txt")

            print_status(f"[*] {ip} SVN 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            url = f"svn://{ip}"
            for username in usernames:
                for password in passwords:
                    print_status(f"[*] {ip} SVN 尝试: {username}/{password}")
                    try:
                        repo = RemoteClient(
                            url,
                            username=username,
                            password=password
                        )
                        # 尝试获取仓库信息
                        repo.info()
                        return f"{ip}[+]SVN存在弱密码: {username}/{password}"
                    except:
                        continue

            return f"{ip}[-]未发现SVN弱密码"
        except ImportError:
            return f"{ip}[!]缺少svn库，无法检测SVN"
        except Exception as e:
            return f"{ip}[!]SVN检测出错: {str(e)}"

    # Redis弱密码检测
    def check_redis(self, ip):
        try:
            import redis
            passwords = self.load_dict("dic_password_redis.txt")

            print_status(f"[*] {ip} Redis 开始检测，尝试 {len(passwords)} 个密码")

            for password in passwords:
                print_status(f"[*] {ip} Redis 尝试密码: {password}")
                try:
                    r = redis.StrictRedis(
                        host=ip,
                        port=6379,
                        password=password,
                        socket_timeout=3
                    )
                    # 尝试执行命令验证权限
                    r.ping()
                    return f"{ip}[+]Redis存在弱密码: {password}"
                except redis.exceptions.AuthenticationError:
                    continue
                except:
                    break

            return f"{ip}[-]未发现Redis弱密码"
        except ImportError:
            return f"{ip}[!]缺少redis库，无法检测Redis"
        except Exception as e:
            return f"{ip}[!]Redis检测出错: {str(e)}"

    # Memcached弱密码检测
    def check_memcached(self, ip):
        try:
            print_status(f"[*] {ip} Memcached 开始检测未授权访问")

            # Memcached通常无密码，这里检测未授权访问
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if sock.connect_ex((ip, 11211)) == 0:
                sock.send(b"stats\n")
                response = sock.recv(1024)
                sock.close()
                if b"STAT version" in response:
                    return f"{ip}[+]Memcached存在未授权访问"

            return f"{ip}[-]Memcached需要认证或无法访问"
        except Exception as e:
            return f"{ip}[!]Memcached检测出错: {str(e)}"

    # Elasticsearch弱密码检测
    def check_elasticsearch(self, ip):
        try:
            usernames = self.load_dict("dic_username_elasticsearch.txt")
            passwords = self.load_dict("dic_password_elasticsearch.txt")

            print_status(f"[*] {ip} Elasticsearch 开始检测，尝试 {len(usernames)} 个用户名和 {len(passwords)} 个密码")

            ports = [9200, 9300]
            for port in ports:
                url = f"http://{ip}:{port}/_cluster/health"
                for username in usernames:
                    for password in passwords:
                        print_status(f"[*] {ip}:{port} Elasticsearch 尝试: {username}/{password}")
                        try:
                            response = requests.get(
                                url,
                                auth=(username, password),
                                timeout=5,
                                verify=False
                            )
                            if response.status_code == 200:
                                return f"{ip}:{port}[+]Elasticsearch存在弱密码: {username}/{password}"
                        except:
                            continue

            return f"{ip}[-]未发现Elasticsearch弱密码"
        except Exception as e:
            return f"{ip}[!]Elasticsearch检测出错: {str(e)}"

    # 详细模式选择
    def select_verbose_mode(self):
        """选择是否显示详细信息"""
        while True:
            choice = input("\n是否显示详细检测过程？(y/N): ").strip().lower()
            if not choice:
                return False
            if choice in ['y', 'yes']:
                return True
            elif choice in ['n', 'no']:
                return False
            else:
                print_red("无效输入，请输入y或n")


# 主函数
def run_weakcheck_scan(args):
    """弱密码扫描入口函数"""
    print_cyan("\n" + "=" * 80)
    print_cyan("          弱密码扫描模块          ")
    print_cyan("=" * 80)

    # 初始化扫描器
    checker = WeakPasswordChecker(threads=args.threads)
    checker.verbose = checker.select_verbose_mode()

    # 提取IP
    if args.url:
        print_cyan(f"[+] 从URL提取IP: {args.url}")
        base_ip = checker.extract_ip_from_url(args.url)
        if not base_ip:
            print_red("[!] 无法从URL提取有效IP，扫描终止")
            return
        print_green(f"[+] 提取到IP: {base_ip}")
    elif args.ip:
        base_ip = args.ip
        if not checker.is_valid_ip(base_ip):
            print_red("[!] 无效IP地址，扫描终止")
            return
    else:
        print_red("[!] 请通过-u或-i指定目标，扫描终止")
        return

    # 选择扫描范围
    print_cyan("\n请选择扫描范围：")
    range_choices = {
        '1': ['single', '单个IP'],
        '2': ['cidr', 'C段（255个IP）'],
        '3': ['b_segment', 'B段（65535个IP）'],
        '4': ['a_segment', 'A段（约1677万个IP）']
    }
    for num, (range_type, desc) in range_choices.items():
        print(f"{num}. {range_type.ljust(10)} - {desc}")

    while True:
        range_choice = input("\n请输入范围选项（1-4）: ").strip()
        if range_choice in range_choices:
            range_type = range_choices[range_choice][0]
            break
        else:
            print_red("无效选项，请输入1-4！")

    # 大网段警告
    if range_type in ['b_segment', 'a_segment']:
        ip_count = 65535 if range_type == 'b_segment' else 16777215
        print_yellow(f"\n[!] 警告：{range_choices[range_choice][1]}，可能需要较长时间")
        confirm = input(Fore.YELLOW + "是否继续？(y/N): ").strip().lower()
        if confirm != 'y':
            print_cyan("[+] 用户取消扫描")
            return

    # 生成IP列表
    ip_list = checker.generate_ip_list(base_ip, range_type)
    if not ip_list:
        print_red("[!] 生成IP列表失败，扫描终止")
        return
    print_green(f"[+] 已生成IP列表，共{len(ip_list)}个IP")

    # 选择检测模块
    selected_modules = checker.select_modules()
    print_green(f"[+] 已选择模块: {', '.join(selected_modules)}")

    # 执行扫描
    results = checker.run_scan(ip_list, selected_modules)

    # 结果汇总
    print_cyan("\n" + "=" * 80)
    print_cyan("          扫描结果汇总          ")
    print_cyan("=" * 80)

    vuln_count = sum(1 for r in results if "[+]" in r)
    print_green(f"[+] 扫描完成 | 总检测点: {len(results)} | 发现弱密码: {vuln_count}")

    # 导出结果
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("弱密码扫描结果\n")
            f.write(f"目标范围: {base_ip}/{range_type}\n")
            f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n")
            for res in results:
                f.write(res + "\n")
        print_green(f"[+] 结果已导出至: {args.output}")

    print_cyan("=" * 80)
