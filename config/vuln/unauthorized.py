import re
import socket
import requests
import json
import concurrent.futures
from colorama import Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse

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


class UnauthorizedChecker:
    def __init__(self, threads=10):
        self.threads = threads
        # 所有检测模块映射表（名称: 方法）
        self.modules = {
            "ftp": self.check_ftp,
            "jboss": self.check_jboss,
            "solr": self.check_solr,
            "weblogic": self.check_weblogic,
            "ldap": self.check_ldap,
            "redis": self.check_redis,
            "nfs": self.check_nfs,
            "zookeeper": self.check_zookeeper,
            "vnc": self.check_vnc,
            "elasticsearch": self.check_elasticsearch,
            "jenkins": self.check_jenkins,
            "kibana": self.check_kibana,
            "ipc": self.check_ipc,
            "druid": self.check_druid,
            "swaggerui": self.check_swaggerui,
            "docker": self.check_docker,
            "rabbitmq": self.check_rabbitmq,
            "memcached": self.check_memcached,
            "dubbo": self.check_dubbo,
            "bt_phpmyadmin": self.check_bt_phpmyadmin,
            "rsync": self.check_rsync,
            "kubernetes_api_server": self.check_kubernetes_api_server,
            "couchdb": self.check_couchdb,
            "spring_boot_actuator": self.check_spring_boot_actuator,
            "uwsgi": self.check_uwsgi,
            "thinkadmin_v6": self.check_thinkadmin_v6,
            "php_fpm_fastcgi": self.check_php_fpm_fastcgi,
            "mongodb": self.check_mongodb,
            "jupyter_notebook": self.check_jupyter_notebook,
            "apache_spark": self.check_apache_spark,
            "docker_registry": self.check_docker_registry,
            "hadoop_yarn": self.check_hadoop_yarn,
            "kong": self.check_kong,
            "wordpress": self.check_wordpress,
            "zabbix": self.check_zabbix,
            "activemq": self.check_activemq,
            "harbor": self.check_harbor,
            "atlassian_crowd": self.check_atlassian_crowd
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

    # 选择检测模块
    def select_modules(self):
        print_cyan("\n可用的未授权访问检测模块：")
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
        results = []
        print_cyan(
            f"\n[+] 开始未授权访问扫描 | 目标IP数: {len(ip_list)} | 模块数: {len(selected_modules)} | 线程数: {self.threads}")

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
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if "[+]" in result:  # 只打印存在漏洞的结果
                            print_red(result)
                        else:
                            print_cyan(result)
                except Exception as e:
                    print_red(f"[!] 扫描出错: {str(e)}")

        return results

    # 执行单个检查
    def run_single_check(self, ip, module):
        try:
            if module in self.modules:
                result = self.modules[module](ip)
                return result
            return f"{ip} 未知模块: {module}"
        except Exception as e:
            return f"{ip} {module} 检测出错: {str(e)}"

    # 以下为所有未授权访问检测函数（完善版）
    def check_ftp(self, ip):
        try:
            import ftplib
            try:
                ftp = ftplib.FTP(ip, timeout=5)
                ftp.login()  # 匿名登录
                ftp.quit()
                return f"{ip}[+]存在FTP未授权访问漏洞（匿名登录）"
            except:
                # 尝试常见弱密码
                weak_passwords = [('admin', 'admin'), ('anonymous', 'anonymous'),
                                  ('ftp', 'ftp'), ('root', 'root')]
                for user, pwd in weak_passwords:
                    try:
                        ftp = ftplib.FTP(ip, timeout=5)
                        ftp.login(user, pwd)
                        ftp.quit()
                        return f"{ip}[+]存在FTP未授权访问漏洞（弱密码: {user}/{pwd}）"
                    except:
                        continue
                return f"{ip}[-]不存在FTP未授权访问漏洞"
        except ImportError:
            return f"{ip}[!]缺少ftplib库，无法检测FTP"
        except Exception as e:
            return f"{ip}[!]FTP检测出错: {str(e)}"

    def check_jboss(self, ip):
        endpoints = [
            f'http://{ip}:8080/jmx-console/',
            f'http://{ip}:8080/console/',
            f'http://{ip}:8080/invoker/JMXInvokerServlet',
            f'https://{ip}:8443/jmx-console/'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code in [200, 403]:
                    if 'jboss' in response.headers.get('Server', '').lower() or 'jboss' in response.text.lower():
                        return f"{ip}[+]存在JBoss未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在JBoss未授权访问漏洞"

    def check_solr(self, ip):
        endpoints = [
            f'http://{ip}:8983/solr/',
            f'http://{ip}:8983/solr/admin/',
            f'https://{ip}:8984/solr/'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200 and 'Apache Solr' in response.text:
                    return f"{ip}[+]存在Solr未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在Solr未授权访问漏洞"

    def check_weblogic(self, ip):
        endpoints = [
            f'http://{ip}:7001/console/login/LoginForm.jsp',
            f'http://{ip}:7001/wls-wsat/CoordinatorPortType',
            f'https://{ip}:7002/console/'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code in [200, 401, 403]:
                    if 'Oracle WebLogic Server' in response.text:
                        return f"{ip}[+]存在WebLogic未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在WebLogic未授权访问漏洞"

    def check_ldap(self, ip):
        try:
            import ldap3
            try:
                server = ldap3.Server(f'ldap://{ip}:389', connect_timeout=5)
                conn = ldap3.Connection(server)
                if conn.bind():
                    conn.unbind()
                    return f"{ip}[+]存在LDAP未授权访问漏洞"
                else:
                    return f"{ip}[-]不存在LDAP未授权访问漏洞"
            except:
                return f"{ip}[-]LDAP连接失败"
        except ImportError:
            return f"{ip}[!]缺少ldap3库，无法检测LDAP"

    def check_redis(self, ip):
        try:
            import redis
            redis_port = 6379
            try:
                r = redis.Redis(host=ip, port=redis_port, socket_timeout=3)
                r.info()  # 尝试获取信息
                return f"{ip}[+]存在Redis未授权访问漏洞"
            except redis.exceptions.AuthenticationError:
                return f"{ip}[-]Redis需要认证，不存在未授权访问"
            except redis.exceptions.ConnectionError:
                return f"{ip}[-]Redis无法连接"
            except Exception as e:
                return f"{ip}[!]Redis检测出错: {str(e)}"
        except ImportError:
            return f"{ip}[!]缺少redis库，无法检测Redis"

    def check_nfs(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 2049))
            sock.close()
            if result == 0:
                return f"{ip}[+]NFS端口开放，可能存在未授权访问漏洞"
            else:
                return f"{ip}[-]NFS端口未开放"
        except Exception as e:
            return f"{ip}[!]NFS检测出错: {str(e)}"

    def check_zookeeper(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex((ip, 2181)) == 0:
                sock.send(b'stat')
                data = sock.recv(1024)
                sock.close()
                if data and b'Zookeeper' in data:
                    return f"{ip}[+]存在Zookeeper未授权访问漏洞"
                else:
                    return f"{ip}[-]不存在Zookeeper未授权访问漏洞"
            else:
                sock.close()
                return f"{ip}[-]Zookeeper端口未开放"
        except Exception as e:
            return f"{ip}[!]Zookeeper检测出错: {str(e)}"

    def check_vnc(self, ip):
        try:
            # 简化检测，只检查端口是否开放
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 5900))
            sock.close()
            if result == 0:
                return f"{ip}[+]VNC端口开放，可能存在未授权访问漏洞"
            else:
                return f"{ip}[-]VNC端口未开放"
        except Exception as e:
            return f"{ip}[!]VNC检测出错: {str(e)}"

    def check_elasticsearch(self, ip):
        endpoints = [
            f'http://{ip}:9200/_cat',
            f'http://{ip}:9200/_nodes',
            f'https://{ip}:9200/_cluster/health'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    return f"{ip}[+]存在Elasticsearch未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在Elasticsearch未授权访问漏洞"

    def check_jenkins(self, ip):
        jenkins_url = f'http://{ip}:8080'
        try:
            response = requests.get(jenkins_url, timeout=5)
            if 'X-Jenkins' in response.headers:
                jobs_url = jenkins_url + "/api/json?tree=jobs[name]"
                jobs_response = requests.get(jobs_url, timeout=5)
                if jobs_response.status_code == 200:
                    return f"{ip}[+]存在Jenkins未授权访问漏洞"
                else:
                    return f"{ip}[-]Jenkins需要认证"
            else:
                return f"{ip}[-]未检测到Jenkins服务"
        except:
            return f"{ip}[-]Jenkins无法连接"

    # 其他检测函数保持提供的代码结构，此处省略（与上面函数风格一致）
    def check_kibana(self, ip):
        endpoints = [
            f'http://{ip}:5601',
            f'http://{ip}:5601/app/dashboards',
            f'http://{ip}:5601/api/saved_objects/_find?type=dashboard'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'Kibana' in response.text:
                    return f"{ip}[+]存在Kibana未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在Kibana未授权访问漏洞"

    def check_ipc(self, ip):
        try:
            import smbclient
            try:
                smbclient.register_session(ip, username='', password='', timeout=5)
                return f"{ip}[+]存在IPC未授权访问漏洞"
            except smbclient.AccessDenied:
                return f"{ip}[-]不存在IPC未授权访问漏洞"
            except:
                return f"{ip}[-]IPC无法连接"
        except ImportError:
            return f"{ip}[!]缺少smbclient库，无法检测IPC"

    def check_druid(self, ip):
        endpoints = [
            f'http://{ip}:8888/druid/index.html',
            f'http://{ip}:8888/druid/console.html',
            f'http://{ip}:8888/druid/sql.html'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'Druid' in response.text:
                    return f"{ip}[+]存在Druid未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在Druid未授权访问漏洞"

    def check_swaggerui(self, ip):
        endpoints = [
            f'http://{ip}/swagger-ui.html',
            f'http://{ip}/v2/api-docs',
            f'http://{ip}/swagger-resources'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'Swagger' in response.text:
                    return f"{ip}[+]存在SwaggerUI未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在SwaggerUI未授权访问漏洞"

    def check_docker(self, ip):
        docker_url = f'http://{ip}:2375/version'
        try:
            response = requests.get(docker_url, timeout=5)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'ApiVersion' in data:
                        return f"{ip}[+]存在Docker未授权访问漏洞"
                except json.JSONDecodeError:
                    pass
            return f"{ip}[-]不存在Docker未授权访问漏洞"
        except:
            return f"{ip}[-]无法连接到Docker守护进程"

    def check_rabbitmq(self, ip):
        endpoints = [
            f'http://{ip}:15672/',
            f'http://{ip}:15672/api/nodes',
            f'http://{ip}:15672/api/queues'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'RabbitMQ Management' in response.text:
                    return f"{ip}[+]存在RabbitMQ未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在RabbitMQ未授权访问漏洞"

    def check_memcached(self, ip):
        try:
            import memcache
            try:
                memcached_client = memcache.Client([f'{ip}:11211'], timeout=5)
                stats = memcached_client.get_stats()
                if len(stats) > 0:
                    return f"{ip}[+]存在Memcached未授权访问漏洞"
                else:
                    return f"{ip}[-]不存在Memcached未授权访问漏洞"
            except:
                return f"{ip}[-]Memcached无法连接"
        except ImportError:
            return f"{ip}[!]缺少memcache库，无法检测Memcached"

    def check_dubbo(self, ip):
        url = f'http://{ip}:8080/'
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and 'dubbo' in response.text.lower():
                return f"{ip}[+]存在Dubbo未授权访问漏洞"
            else:
                return f"{ip}[-]不存在Dubbo未授权访问漏洞"
        except:
            return f"{ip}[-]Dubbo无法连接"

    def check_bt_phpmyadmin(self, ip):
        endpoints = [
            f'http://{ip}/phpmyadmin/',
            f'http://{ip}/phpmyadmin/index.php',
            f'http://{ip}:888/phpmyadmin/'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'phpMyAdmin' in response.text:
                    return f"{ip}[+]存在宝塔phpMyAdmin未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在宝塔phpMyAdmin未授权访问漏洞"

    def check_rsync(self, ip):
        try:
            import subprocess
            import shlex
            command = f"rsync --list-only rsync://{ip}/"
            process = subprocess.Popen(
                shlex.split(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10
            )
            output, error = process.communicate()
            if process.returncode == 0 and output:
                return f"{ip}[+]存在Rsync未授权访问漏洞"
            else:
                return f"{ip}[-]不存在Rsync未授权访问漏洞"
        except ImportError:
            return f"{ip}[!]无法执行Rsync检测命令"
        except Exception as e:
            return f"{ip}[!]Rsync检测出错: {str(e)}"

    def check_kubernetes_api_server(self, ip):
        api_server_url = f'https://{ip}:6443/api/'
        try:
            response = requests.get(api_server_url, timeout=5, verify=False)
            if response.status_code == 401:
                return f"{ip}[+]存在Kubernetes API未授权访问漏洞"
            else:
                return f"{ip}[-]不存在Kubernetes API未授权访问漏洞"
        except:
            return f"{ip}[-]Kubernetes无法连接"

    def check_couchdb(self, ip):
        endpoints = [
            f'http://{ip}:5984/_utils/',
            f'http://{ip}:5984/_all_dbs',
            f'http://{ip}:5984/_stats'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'CouchDB' in response.text:
                    return f"{ip}[+]存在CouchDB未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在CouchDB未授权访问漏洞"

    def check_spring_boot_actuator(self, ip):
        endpoints = [
            f'http://{ip}:8080/actuator/',
            f'http://{ip}:8080/actuator/health',
            f'http://{ip}:8080/actuator/env'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    return f"{ip}[+]存在Spring Boot Actuator未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在Spring Boot Actuator未授权访问漏洞"

    def check_uwsgi(self, ip):
        endpoints = [
            f'http://{ip}:1717/',
            f'http://{ip}:1717/admin',
            f'http://{ip}:1717/stats'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'uWSGI' in response.text:
                    return f"{ip}[+]存在uWSGI未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在uWSGI未授权访问漏洞"

    def check_thinkadmin_v6(self, ip):
        endpoints = [
            f'http://{ip}/index/login.html',
            f'http://{ip}/admin',
            f'http://{ip}/api'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'ThinkAdmin' in response.text:
                    return f"{ip}[+]存在ThinkAdmin V6未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在ThinkAdmin V6未授权访问漏洞"

    def check_php_fpm_fastcgi(self, ip):
        endpoints = [
            f'http://{ip}/php-fpm_status',
            f'http://{ip}/status.php',
            f'http://{ip}/ping.php'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'PHP' in response.text:
                    return f"{ip}[+]存在PHP-FPM Fastcgi未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在PHP-FPM Fastcgi未授权访问漏洞"

    def check_mongodb(self, ip):
        try:
            import pymongo
            mongodb_url = f'mongodb://{ip}:27017/'
            try:
                client = pymongo.MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
                client.list_database_names()  # 尝试列出数据库
                return f"{ip}[+]存在MongoDB未授权访问漏洞"
            except pymongo.errors.OperationFailure:
                return f"{ip}[-]MongoDB需要认证"
            except:
                return f"{ip}[-]MongoDB无法连接"
        except ImportError:
            return f"{ip}[!]缺少pymongo库，无法检测MongoDB"

    def check_jupyter_notebook(self, ip):
        endpoints = [
            f'http://{ip}:8888/',
            f'http://{ip}:8888/api',
            f'http://{ip}:8888/user'
        ]
        for url in endpoints:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200 and 'Jupyter' in response.text:
                    return f"{ip}[+]存在Jupyter Notebook未授权访问漏洞（{url}）"
            except:
                continue
        return f"{ip}[-]不存在Jupyter Notebook未授权访问漏洞"

    def check_apache_spark(self, ip):
        spark_url = f'http://{ip}:8080/'
        try:
            response = requests.get(spark_url, timeout=5)
            if response.status_code == 200 and 'Spark Master' in response.text:
                return f"{ip}[+]存在Apache Spark未授权访问漏洞"
            else:
                return f"{ip}[-]不存在Apache Spark未授权访问漏洞"
        except:
            return f"{ip}[-]Spark无法连接"

    def check_docker_registry(self, ip):
        registry_url = f'http://{ip}/v2/_catalog'
        try:
            response = requests.get(registry_url, timeout=5)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    if 'repositories' in json_data:
                        return f"{ip}[+]存在Docker Registry未授权访问漏洞"
                except json.JSONDecodeError:
                    pass
            return f"{ip}[-]不存在Docker Registry未授权访问漏洞"
        except:
            return f"{ip}[-]Registry无法连接"

    def check_hadoop_yarn(self, ip):
        yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'
        try:
            response = requests.get(yarn_url, timeout=5)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    if 'resourceManagerVersion' in json_data.get('clusterInfo', {}):
                        return f"{ip}[+]存在Hadoop YARN未授权访问漏洞"
                except json.JSONDecodeError:
                    pass
            return f"{ip}[-]不存在Hadoop YARN未授权访问漏洞"
        except:
            return f"{ip}[-]YARN无法连接"

    def check_kong(self, ip):
        kong_url = f'http://{ip}:8001/'
        try:
            response = requests.get(kong_url, timeout=5)
            if response.status_code == 200 and 'Welcome to Kong' in response.text:
                return f"{ip}[+]存在Kong未授权访问漏洞"
            else:
                return f"{ip}[-]不存在Kong未授权访问漏洞"
        except:
            return f"{ip}[-]Kong无法连接"

    def check_wordpress(self, ip):
        wordpress_url = f'http://{ip}/wp-login.php'
        try:
            response = requests.get(wordpress_url, timeout=5)
            if response.status_code == 200 and 'WordPress' in response.text:
                return f"{ip}[+]存在WordPress未授权访问漏洞（可能存在弱密码）"
            else:
                return f"{ip}[-]不存在WordPress未授权访问漏洞"
        except:
            return f"{ip}[-]WordPress无法连接"

    def check_zabbix(self, ip):
        zabbix_url = f'http://{ip}/zabbix/jsrpc.php'
        headers = {
            'Content-Type': 'application/json-rpc',
            'User-Agent': 'Mozilla/5.0'
        }
        data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
        try:
            response = requests.post(zabbix_url, headers=headers, data=data, timeout=5)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    if 'result' in json_data:
                        return f"{ip}[+]存在Zabbix未授权访问漏洞"
                except json.JSONDecodeError:
                    pass
            return f"{ip}[-]不存在Zabbix未授权访问漏洞"
        except:
            return f"{ip}[-]Zabbix无法连接"

    def check_activemq(self, ip):
        activemq_url = f'http://{ip}:8161/admin/'
        try:
            response = requests.get(activemq_url, timeout=5)
            if response.status_code == 200 and 'Apache ActiveMQ' in response.text:
                return f"{ip}[+]存在ActiveMQ未授权访问漏洞"
            else:
                return f"{ip}[-]不存在ActiveMQ未授权访问漏洞"
        except:
            return f"{ip}[-]ActiveMQ无法连接"

    def check_harbor(self, ip):
        harbor_url = f'http://{ip}/api/v2.0/statistics'
        try:
            response = requests.get(harbor_url, timeout=5)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    if 'total_projects' in json_data:
                        return f"{ip}[+]存在Harbor未授权访问漏洞"
                except json.JSONDecodeError:
                    pass
            return f"{ip}[-]不存在Harbor未授权访问漏洞"
        except:
            return f"{ip}[-]Harbor无法连接"

    def check_atlassian_crowd(self, ip):
        crowd_url = f'http://{ip}:8095/crowd/'
        try:
            response = requests.get(crowd_url, timeout=5)
            if response.status_code == 200 and 'Atlassian Crowd' in response.text:
                return f"{ip}[+]存在Atlassian Crowd未授权访问漏洞"
            else:
                return f"{ip}[-]不存在Atlassian Crowd未授权访问漏洞"
        except:
            return f"{ip}[-]Atlassian Crowd无法连接"


# 主函数
def run_unauthorized_scan(args):
    """未授权访问漏洞扫描入口函数"""
    print_cyan("\n" + "=" * 80)
    print_cyan("          未授权访问漏洞扫描模块          ")
    print_cyan("=" * 80)

    # 初始化扫描器
    checker = UnauthorizedChecker(threads=args.threads)

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
    print_green(f"[+] 扫描完成 | 总检测点: {len(results)} | 发现漏洞: {vuln_count}")

    # 导出结果
    if args.output and results:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("未授权访问漏洞扫描结果\n")
            f.write(f"目标范围: {base_ip}/{range_type}\n")
            f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n")
            for res in results:
                f.write(res + "\n")
        print_green(f"[+] 结果已导出至: {args.output}")

    print_cyan("=" * 80)


# 补充时间模块导入
import time