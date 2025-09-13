import requests
import threading
import re
import datetime
import time
import socket
import ipaddress  # 新增：用于IP网段判断
import pygeoip
import geoip2.database  # 新增：用于ASN查询
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from colorama import Fore, Style
from ipwhois import IPWhois
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 忽略HTTPS证书警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 线程锁和结果存储
lock = threading.Lock()
results = []
progress = 0
total_ips = 0

# 初始化GeoIP数据库
try:
    gi = pygeoip.GeoIP('config/data/GeoLiteCity.dat')
    GEOIP_AVAILABLE = True
except Exception as e:
    print(Fore.RED + f"[!] 地理信息数据库加载失败: {str(e)}")
    GEOIP_AVAILABLE = False

try:
    asn_reader = geoip2.database.Reader('config/data/GeoLite2-ASN.mmdb')
    ASN_AVAILABLE = True
except Exception as e:
    print(Fore.RED + f"[!] ASN数据库加载失败: {str(e)}")
    print(Fore.YELLOW + "[!] CDN检测功能将受影响，建议下载GeoLite2-ASN.mmdb放置于config/data/目录")
    ASN_AVAILABLE = False

CDN_IP_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15','104.16.0.0/12',
        '172.64.0.0/13', '131.0.72.0/22', '13.124.199.0/24', '144.220.0.0/16', '34.226.14.0/24', '52.124.128.0/17',
        '54.230.0.0/16', '54.239.128.0/18', '52.82.128.0/19', '99.84.0.0/16', '52.15.127.128/26', '35.158.136.0/24',
        '52.57.254.0/24', '18.216.170.128/25', '13.54.63.128/26', '13.59.250.0/26', '13.210.67.128/26',
        '35.167.191.128/26', '52.47.139.0/24', '52.199.127.192/26', '52.212.248.0/26', '205.251.192.0/19',
        '52.66.194.128/26', '54.239.192.0/19', '70.132.0.0/18', '13.32.0.0/15', '13.224.0.0/14', '13.113.203.0/24',
        '34.195.252.0/24', '35.162.63.192/26', '34.223.12.224/27', '13.35.0.0/16', '204.246.172.0/23',
        '204.246.164.0/22', '52.56.127.0/25', '204.246.168.0/22', '13.228.69.0/24', '34.216.51.0/25',
        '71.152.0.0/17', '216.137.32.0/19', '205.251.249.0/24', '99.86.0.0/16', '52.46.0.0/18', '52.84.0.0/15',
        '54.233.255.128/26', '130.176.0.0/16', '64.252.64.0/18', '52.52.191.128/26', '204.246.174.0/23',
        '64.252.128.0/18', '205.251.254.0/24', '143.204.0.0/16', '205.251.252.0/23', '52.78.247.128/26',
        '204.246.176.0/20', '52.220.191.0/26', '13.249.0.0/16', '54.240.128.0/18', '205.251.250.0/23',
        '52.222.128.0/17', '54.182.0.0/16', '54.192.0.0/16', '34.232.163.208/29', '58.250.143.0/24',
        '58.251.121.0/24', '59.36.120.0/24', '61.151.163.0/24', '101.227.163.0/24', '111.161.109.0/24',
        '116.128.128.0/24', '123.151.76.0/24', '125.39.46.0/24', '140.207.120.0/24', '180.163.22.0/24',
        '183.3.254.0/24', '223.166.151.0/24', '113.107.238.0/24', '106.42.25.0/24', '183.222.96.0/24',
        '117.21.219.0/24', '116.55.250.0/24', '111.202.98.0/24', '111.13.147.0/24', '122.228.238.0/24',
        '58.58.81.0/24', '1.31.128.0/24', '123.155.158.0/24', '106.119.182.0/24', '180.97.158.0/24',
        '113.207.76.0/24', '117.23.61.0/24', '118.212.233.0/24', '111.47.226.0/24', '219.153.73.0/24',
        '113.200.91.0/24', '1.32.240.0/24', '203.90.247.0/24', '183.110.242.0/24', '202.162.109.0/24',
        '182.23.211.0/24', '1.32.242.0/24', '1.32.241.0/24', '202.162.108.0/24', '185.254.242.0/24',
        '109.94.168.0/24', '109.94.169.0/24', '1.32.243.0/24', '61.120.154.0/24', '1.255.41.0/24',
        '112.90.216.0/24', '61.213.176.0/24', '1.32.238.0/24', '1.32.239.0/24', '1.32.244.0/24', '111.32.135.0/24',
        '111.32.136.0/24', '125.39.174.0/24', '125.39.239.0/24', '112.65.73.0/24', '112.65.74.0/24',
        '112.65.75.0/24', '119.84.92.0/24', '119.84.93.0/24', '113.207.100.0/24', '113.207.101.0/24',
        '113.207.102.0/24', '180.163.188.0/24', '180.163.189.0/24', '163.53.89.0/24', '101.227.206.0/24',
        '101.227.207.0/24', '119.188.97.0/24', '119.188.9.0/24', '61.155.149.0/24', '61.156.149.0/24',
        '61.155.165.0/24', '61.182.137.0/24', '61.182.136.0/24', '120.52.29.0/24', '120.52.113.0/24',
        '222.216.190.0/24', '219.159.84.0/24', '183.60.235.0/24', '116.31.126.0/24', '116.31.127.0/24',
        '117.34.13.0/24', '117.34.14.0/24', '42.236.93.0/24', '42.236.94.0/24', '119.167.246.0/24',
        '150.138.149.0/24', '150.138.150.0/24', '150.138.151.0/24', '117.27.149.0/24', '59.51.81.0/24',
        '220.170.185.0/24', '220.170.186.0/24', '183.61.236.0/24', '14.17.71.0/24', '119.147.134.0/24',
        '124.95.168.0/24', '124.95.188.0/24', '61.54.46.0/24', '61.54.47.0/24', '101.71.55.0/24', '101.71.56.0/24',
        '183.232.51.0/24', '183.232.53.0/24', '157.255.25.0/24', '157.255.26.0/24', '112.25.90.0/24',
        '112.25.91.0/24', '58.211.2.0/24', '58.211.137.0/24', '122.190.2.0/24', '122.190.3.0/24', '183.61.177.0/24',
        '183.61.190.0/24', '117.148.160.0/24', '117.148.161.0/24', '115.231.186.0/24', '115.231.187.0/24',
        '113.31.27.0/24', '222.186.19.0/24', '122.226.182.0/24', '36.99.18.0/24', '123.133.84.0/24',
        '221.204.202.0/24', '42.236.6.0/24', '61.130.28.0/24', '61.174.9.0/24', '223.94.66.0/24', '222.88.94.0/24',
        '61.163.30.0/24', '223.94.95.0/24', '223.112.227.0/24', '183.250.179.0/24', '120.241.102.0/24',
        '125.39.5.0/24', '124.193.166.0/24', '122.70.134.0/24', '111.6.191.0/24', '122.228.198.0/24',
        '121.12.98.0/24', '60.12.166.0/24', '118.180.50.0/24', '183.203.7.0/24', '61.133.127.0/24',
        '113.7.183.0/24', '210.22.63.0/24', '60.221.236.0/24', '122.227.237.0/24', '123.6.13.0/24',
        '202.102.85.0/24', '61.160.224.0/24', '182.140.227.0/24', '221.204.14.0/24', '222.73.144.0/24',
        '61.240.144.0/24', '36.27.212.0/24', '125.88.189.0/24', '120.52.18.0/24', '119.84.15.0/24',
        '180.163.224.0/24', '46.51.216.0/21','119.84.129.0/24', '221.236.11.0/24', '118.123.241.0/24',
        '122.225.34.0/24'
]

CDN_ASNS = [
    '55770', '49846', '49249', '48163', '45700', '43639', '39836',
    '393560', '393234', '36183', '35994', '35993', '35204', '34850',
    '34164', '33905', '32787', '31377', '31110', '31109', '31108',
    '31107', '30675', '24319', '23903', '23455', '23454', '22207',
    '21399', '21357', '21342', '20940', '20189', '18717', '18680',
    '17334', '16702', '16625', '12222', '61107', '60922', '60626',
    '49689', '209101', '201585', '136764', '135429', '135295', '133496',
    '395747', '394536', '209242', '203898', '202623', '14789', '133877',
    '13335', '132892'
]

# 端口扫描核心配置
SIGNS = (
    b'smb|smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
    # b"xmpp|xmpp|^\<\?xml version='1.0'\?\>",
    b'netbios|netbios|^\x79\x08.*BROWSE',
    b'http|http|HTTP/1.1',
    b'netbios|netbios|^\x79\x08.\x00\x00\x00\x00',
    b'netbios|netbios|^\x05\x00\x0d\x03',
    b'netbios|netbios|^\x82\x00\x00\x00',
    b'netbios|netbios|\x83\x00\x00\x01\x8f',
    b'backdoor|backdoor|^500 Not Loged in',
    b'backdoor|backdoor|GET: command',
    b'backdoor|backdoor|sh: GET:',
    b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
    b'backdoor|backdoor|^bash[$#]',
    b'backdoor|backdoor|^sh[$#]',
    b'backdoor|backdoor|^Microsoft Windows',
    b'db2|db2|.*SQLDB2RA',
    b'dell-openmanage|dell-openmanage|^\x4e\x00\x0d',
    b'finger|finger|^\r\n	Line	  User',
    b'finger|finger|Line	 User',
    b'finger|finger|Login name: ',
    b'ftp|ftp|^220.*\n331',
    b'ftp|ftp|^220.*\n530',
    b'ftp|ftp|^220.*FTP',
    b'ldap|ldap|^\x30\x0c\x02\x01\x01\x61',
    b'rdp|rdp|^\x03\x00\x00\x0b',
    b'rdp|rdp|^\x03\x00\x00\x11',
    b'msrpc|msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    b'mssql|mssql|^\x05\x6e\x00',
    b'mysql|mysql|mysql_native_password',
    b'mysql|mysql|^\x19\x00\x00\x00\x0a',
    b'postgresql|postgres|Invalid packet length',
    b'rsync|rsync|^@RSYNCD:',
    b'ssh|ssh|^SSH-',
    b'http|http|HTTP/1.0',
    b'https|https|HTTPS port',
    b'https|https|Location: https',
    b'redis|redis|^-ERR unknown command',
    b'memcached|memcached|^ERROR\r\n',
)

PORTS = [21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 135, 139, 143, 161,
         389, 443, 445, 465, 512, 513, 514, 587, 631, 636, 873, 902, 990,
         993, 995, 1080, 1099, 1433, 1434, 1521, 1723, 2082, 2083, 2181,
         2222, 2375, 3000, 3128, 3306, 3389, 3690, 4440, 4848, 5000, 5432,
         5900, 5984, 6082, 6379, 7001, 8000, 8080, 8081, 8088, 8888, 9000,
         9090, 9200, 9300, 10000, 11211, 27017]

SERVER_MAP = {
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
    '53': 'DNS', '80': 'HTTP', '443': 'HTTPS', '110': 'POP3',
    '139': 'NetBIOS', '143': 'IMAP', '445': 'SMB', '3306': 'MySQL',
    '3389': 'RDP', '5900': 'VNC', '6379': 'Redis', '8080': 'HTTP代理',
    '27017': 'MongoDB', '5432': 'PostgreSQL', '9200': 'Elasticsearch'
}


# 颜色输出函数
def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)


def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)


def print_yellow(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


# 基础工具函数
def is_valid_ip(ip):
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    for group in match.groups():
        if int(group) < 0 or int(group) > 255:
            return False
    return True


def is_private_ip(ip):
    private_ranges = [re.compile(r'^10\.'), re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'), re.compile(r'^192\.168\.')]
    for pattern in private_ranges:
        if pattern.match(ip):
            return True
    return False


def get_geo_info(ip):
    if not GEOIP_AVAILABLE:
        return None
    try:
        rec = gi.record_by_name(ip)
        return {
            'city': rec.get('city', '未知'),
            'country': rec.get('country_name', '未知'),
            'latitude': rec.get('latitude', '未知'),
            'longitude': rec.get('longitude', '未知')
        } if rec else None
    except Exception:
        return None


# 新增：CDN检测核心函数
def check_cdn(ip):
    """检测IP是否属于CDN服务"""
    cdn_info = {
        'is_cdn': False,
        'reason': '未检测到CDN特征',
        'asn': None,
        'isp': None
    }

    # 1. 检查IP是否在已知CDN IP段中
    try:
        ip_addr = ipaddress.ip_address(ip)
        for cidr in CDN_IP_RANGES:
            if ip_addr in ipaddress.ip_network(cidr, strict=False):
                cdn_info['is_cdn'] = True
                cdn_info['reason'] = f'IP在已知CDN网段 {cidr} 中'
                return cdn_info
    except Exception as e:
        cdn_info['reason'] = f'IP网段检测错误: {str(e)}'

    # 2. 检查ASN是否属于已知CDN运营商
    if ASN_AVAILABLE:
        try:
            response = asn_reader.asn(ip)
            asn = str(response.autonomous_system_number)
            isp = response.autonomous_system_organization

            cdn_info['asn'] = asn
            cdn_info['isp'] = isp

            if asn in CDN_ASNS:
                cdn_info['is_cdn'] = True
                cdn_info['reason'] = f'ASN {asn} ({isp}) 属于已知CDN运营商'
        except Exception as e:
            cdn_info['reason'] = f'ASN查询错误: {str(e)}'

    return cdn_info


# 端口扫描核心类
class PortScanner:
    def __init__(self, ip, thread_num=20):
        self.ip = ip
        self.thread_num = thread_num
        self.open_ports = []
        self.lock = threading.Lock()

    def _probe_service(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.ip, port))
            if result != 0:
                sock.close()
                return None

            # 发送探测包
            probe = b"GET / HTTP/1.0\r\n\r\n"
            sock.sendall(probe)
            response = sock.recv(256)
            sock.close()

            # 匹配服务特征
            service = SERVER_MAP.get(str(port), f"未知服务({port})")
            for pattern in SIGNS:
                parts = pattern.split(b'|')
                if len(parts) < 3:
                    continue
                if re.search(parts[2], response, re.IGNORECASE):
                    service = f"{parts[1].decode()}({port})"
                    break
            return {
                'port': port,
                'service': service,
                'status': 'open'
            }
        except (socket.timeout, ConnectionResetError):
            return None
        except Exception:
            return None

    def _scan_port(self, port):
        result = self._probe_service(port)
        if result:
            with self.lock:
                self.open_ports.append(result)

    def run(self):
        with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
            executor.map(self._scan_port, PORTS)
        self.open_ports.sort(key=lambda x: x['port'])
        return self.open_ports


# Web服务发现模块
def check_web_port(ip, port):
    protocols = [('http', 80), ('https', 443)]
    if port not in [80, 443]:
        check_protocols = ['http', 'https']
    else:
        check_protocols = [p for p, p_port in protocols if p_port == port]

    for proto in check_protocols:
        try:
            url = f'{proto}://{ip}:{port}'
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 11; Windows NT 6.3)'}
            res = requests.get(
                url,
                timeout=2,
                headers=headers,
                verify=False,
                allow_redirects=True
            )

            server = res.headers.get('Server', '未知').split()[0] if 'Server' in res.headers else '未知'
            title = "无标题"
            try:
                soup = BeautifulSoup(res.content, 'lxml')
                if soup.title:
                    title = soup.title.text.strip('\n').strip()[:50]
            except:
                title = "解析失败"

            return {
                'ip': ip,
                'port': port,
                'protocol': proto,
                'url': url,
                'status_code': res.status_code,
                'server': server,
                'title': title
            }
        except requests.exceptions.RequestException:
            continue
    return None


# 动态输出单个IP的扫描结果
def run_module_scan(ip, module, header, output_file=None, debug=False, thread_num=10):
    global results, progress
    result = {
        'ip': ip, 'module': module, 'status': 'success',
        'data': {}, 'message': ""
    }
    geo_info = get_geo_info(ip) if GEOIP_AVAILABLE else None

    # 基础信息模块
    if module == 'base':
        is_private = is_private_ip(ip)
        # 新增：在基础信息中加入CDN检测
        cdn_info = check_cdn(ip) if ASN_AVAILABLE or CDN_IP_RANGES else None

        result['data'] = {
            'private': is_private,
            'private_desc': '内网IP' if is_private else '公网IP',
            'geo_info': geo_info,
            'cdn_info': cdn_info  # 新增CDN信息
        }
        result['message'] = '基础信息查询完成'

    elif module == 'domain':
        api_url = f'http://api.webscan.cc/?action=query&ip={ip}'
        try:
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            api_domain_data = response.json()

            # 检查是否有数据返回
            if api_domain_data:  # 如果返回的列表不为空
                result['data'] = {'domain_info': api_domain_data}
                result['message'] = f'IP {ip} 绑定的域名关联信息查询完成，共找到 {len(api_domain_data)} 条记录'
            else:  # 列表为空的情况
                result['status'] = 'error'
                result['message'] = f'IP {ip} 未查询到绑定的域名信息'

        except Exception as e:
            result['data'] = {}
            result['status'] = 'error'
            result['message'] = f'域名查询失败：{str(e)}'
    # RDAP注册信息模块
    elif module == 'rdap':
        try:
            obj = IPWhois(ip)
            # 增加超时设置
            rdap_data = obj.lookup_rdap(depth=1, timeout=10)

            # 更健壮的数据提取方式
            asn = rdap_data.get('asn', '未知')
            network_name = '未知'
            if 'network' in rdap_data and isinstance(rdap_data['network'], dict):
                network_name = rdap_data['network'].get('name', '未知')

            # 尝试多种可能的国家代码路径
            country_code = rdap_data.get('asn_country_code', '未知')
            if country_code == '未知':
                country_code = rdap_data.get('network', {}).get('country', '未知')

            result['data'] = {
                'asn': asn,
                'network': network_name,
                'country': country_code,
                'geo_info': geo_info,
                'raw_data_available': bool(rdap_data)  # 标识是否有原始数据
            }
            result['message'] = 'RDAP信息查询完成'

        except Exception as e:
            result['status'] = 'error'
            # 更具体的错误信息
            if isinstance(e, TimeoutError):
                result['message'] = f'RDAP查询超时: {str(e)}'
            elif 'not found' in str(e).lower():
                result['message'] = f'未找到该IP的RDAP信息: {str(e)}'
            else:
                result['message'] = f'RDAP查询失败: {str(e)}'
            result['data'] = {'geo_info': geo_info}

    # Web服务发现模块
    elif module == 'web_discovery':
        web_ports = [80, 443, 8080, 81, 8081, 7001, 8000, 8088, 8888]
        web_results = []
        for port in web_ports:
            res = check_web_port(ip, port)
            if res:
                web_results.append(res)

        if web_results:
            result['data'] = {
                'web_services': web_results,
                'geo_info': geo_info
            }
            result['message'] = f"发现 {len(web_results)} 个活跃Web服务"
        else:
            result['status'] = 'empty'
            result['data'] = {'geo_info': geo_info}
            result['message'] = "未发现活跃Web服务"

    # 地理信息模块
    elif module == 'geo':
        if geo_info:
            result['data'] = geo_info
            result['message'] = "地理信息查询完成"
        else:
            result['status'] = 'error'
            result['message'] = "地理信息查询失败"

    # 端口扫描模块
    elif module == 'port_scan':
        scanner = PortScanner(ip, thread_num=thread_num)
        open_ports = scanner.run()

        if open_ports:
            result['data'] = {
                'open_ports': open_ports,
                'total': len(open_ports),
                'geo_info': geo_info
            }
            result['message'] = f"发现 {len(open_ports)} 个开放端口"
        else:
            result['status'] = 'empty'
            result['data'] = {'geo_info': geo_info}
            result['message'] = "未发现开放端口"

    # 新增：CDN检测模块
    elif module == 'cdn':
        cdn_info = check_cdn(ip)
        result['data'] = {
            'cdn_info': cdn_info,
            'geo_info': geo_info
        }
        result['message'] = "CDN检测完成"

    # 综合信息模块
    elif module == 'full':
        # 整合所有模块数据，包括新增的CDN检测
        web_results = []
        for port in [80, 443, 8080]:
            res = check_web_port(ip, port)
            if res:
                web_results.append(res)

        scanner = PortScanner(ip, thread_num=min(10, thread_num))
        open_ports = scanner.run()

        # 新增：综合信息中加入CDN检测
        cdn_info = check_cdn(ip) if ASN_AVAILABLE or CDN_IP_RANGES else None

        rdap_data = {}
        try:
            obj = IPWhois(ip)
            rdap_data = obj.lookup_rdap(depth=1)
        except:
            pass

        result['data'] = {
            'private': is_private_ip(ip),
            'rdap': {
                'asn': rdap_data.get('asn', '未知'),
                'country': rdap_data.get('asn_country_code', '未知')
            },
            'web_services': web_results,
            'open_ports': open_ports,
            'geo_info': geo_info,
            'cdn_info': cdn_info  # 新增CDN信息
        }
        result['message'] = f"综合扫描完成（Web服务: {len(web_results)}, 开放端口: {len(open_ports)}）"

    # 加锁更新进度和结果
    with lock:
        results.append(result)
        progress += 1
        print_progress()

    # 动态输出结果
    if result['status'] == 'success' and (result['data'] or '发现' in result['message']):
        print_cyan(f"\n{'=' * 70}")
        print_cyan(f"[IP: {ip}] 扫描完成（{progress}/{total_ips}）")
        print_cyan(f"[结果] {result['message']}")

        # 显示地理信息
        if geo_info and geo_info.get('country') != '未知':
            print_yellow(f"[地理信息] 国家: {geo_info['country']} | 城市: {geo_info['city']}")

        # 新增：显示CDN检测结果
        if 'cdn_info' in result['data'] and result['data']['cdn_info']:
            cdn_status = "是" if result['data']['cdn_info']['is_cdn'] else "否"
            print_yellow(f"[CDN状态] {cdn_status} | 原因: {result['data']['cdn_info']['reason']}")
            if result['data']['cdn_info']['asn']:
                print_yellow(
                    f"[网络信息] ASN: {result['data']['cdn_info']['asn']} | ISP: {result['data']['cdn_info']['isp']}")

        # 显示Web服务信息
        if 'web_services' in result['data'] and result['data']['web_services']:
            print_cyan("[Web服务]")
            for item in result['data']['web_services']:
                if item['protocol'] == 'https':
                    print_green(f"  {item['url']} | 状态码: {item['status_code']} | 标题: {item['title']}")
                else:
                    print_yellow(f"  {item['url']} | 状态码: {item['status_code']} | 标题: {item['title']}")

        # 显示RDAP注册信息
        if 'asn' in result['data'] and result['data']['asn'] != '未知':
            print_cyan("[RDAP注册信息]")
            print_green(f"  ASN: {result['data']['asn']}")
            print_green(f"  网络名称: {result['data']['network']}")
            print_green(f"  国家/地区: {result['data']['country']}")
        # 显示域名信息
        if 'domain_info' in result['data'] and result['data']['domain_info']:
            print_cyan("[关联域名]")
            for item in result['data']['domain_info']:
                # 区分显示域名和可能的IP（如果有）
                if item['domain'].count('.') >= 2 or item['domain'].endswith(('.com', '.net', '.org', '.cn')):
                    print_green(f"  域名: {item['domain']} | 标题: {item['title']}")
                else:
                    print_yellow(f"  IP绑定: {item['domain']} | 标题: {item['title']}")
        # 显示端口信息
        if 'open_ports' in result['data'] and result['data']['open_ports']:
            print_cyan("[开放端口]")
            for item in result['data']['open_ports']:
                print_green(f"  端口: {item['port']} | 服务: {item['service']}")

        print_cyan(f"{'=' * 70}")

    # 实时写入文件
    if output_file and result['status'] == 'success' and result['data']:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(f"\n[IP: {ip}] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if geo_info:
                f.write(f"地理信息: 国家={geo_info['country']}, 城市={geo_info['city']}\n")

            # 新增：写入CDN信息到文件
            if 'cdn_info' in result['data'] and result['data']['cdn_info']:
                cdn_status = "是" if result['data']['cdn_info']['is_cdn'] else "否"
                f.write(f"CDN状态: {cdn_status} | 原因: {result['data']['cdn_info']['reason']}\n")
                if result['data']['cdn_info']['asn']:
                    f.write(
                        f"网络信息: ASN={result['data']['cdn_info']['asn']}, ISP={result['data']['cdn_info']['isp']}\n")

            if 'web_services' in result['data'] and result['data']['web_services']:
                f.write("Web服务:\n")
                for item in result['data']['web_services']:
                    f.write(f"  {item['url']} | 状态码: {item['status_code']} | 标题: {item['title']}\n")

            if 'open_ports' in result['data'] and result['data']['open_ports']:
                f.write("开放端口:\n")
                for item in result['data']['open_ports']:
                    f.write(f"  端口 {item['port']}: {item['service']}\n")


# 进度条显示
def print_progress():
    global progress, total_ips
    if total_ips > 10000 and progress % 100 != 0:
        return  # 大网段减少刷新频率
    bar_length = 50
    filled_length = int(progress * bar_length // total_ips)
    bar = '#' * filled_length + '-' * (bar_length - filled_length)
    percent = (progress / total_ips) * 100
    print(f"\r{Fore.CYAN}扫描进度: [{bar}] {progress}/{total_ips} ({percent:.1f}%)", end='', flush=True)


# 主扫描函数
def ip_info_scan(args, scan_module, ip_list, debug=False):
    global results, progress, total_ips
    results = []
    progress = 0
    total_ips = len(ip_list)
    max_threads = args.threads or 10

    # 新增：CDN检测模块提示
    if scan_module == 'cdn':
        if not ASN_AVAILABLE and not CDN_IP_RANGES:
            print(Fore.YELLOW + "[!] 警告：CDN检测数据不完整，结果可能不准确")

    # 大网段扫描提示
    if total_ips > 10000:
        print_cyan("\n" + "=" * 70)
        print_cyan(f"[!] 注意：正在扫描大网段（{total_ips}个IP），建议后台运行")
        print_cyan(f"[!] 扫描估计时间：{total_ips / max_threads / 60:.2f} 分钟（按每个IP 1秒估算）")
        print_cyan("=" * 70 + "\n")

    print_cyan("\n" + "=" * 70)
    print_cyan(f"[+] 开始扫描（共{total_ips}个IP） | 模块: {scan_module}")
    print_cyan(f"[+] 线程数：{max_threads} | 时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_cyan("=" * 70 + "\n")

    # 模块特定信息
    if scan_module == 'port_scan':
        print_cyan(f"[+] 端口扫描范围：{len(PORTS)} 个常见端口")
    if scan_module == 'cdn':
        print_cyan(f"[+] CDN检测方式：IP段匹配 + ASN分析")
    if GEOIP_AVAILABLE:
        print_cyan(f"[+] 已启用地理信息查询")
    if ASN_AVAILABLE:
        print_cyan(f"[+] 已启用ASN信息查询（用于CDN检测）")
    print_cyan("=" * 70 + "\n")

    # 初始化输出文件
    output_file = args.output
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"C段扫描结果（{ip_list[0].rsplit('.', 1)[0]}.1-{ip_list[-1].rsplit('.', 1)[1]}\n")
            f.write(f"扫描模块: {scan_module} | 时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"线程数: {max_threads} | 扫描IP总数: {total_ips}\n")
            f.write("=" * 70 + "\n\n")

    # 多线程扫描
    threads = []
    for ip in ip_list:
        while threading.active_count() > max_threads:
            time.sleep(0.1)
        thread = threading.Thread(
            target=run_module_scan,
            args=(ip, scan_module, None, output_file, debug),
            kwargs={'thread_num': max_threads}
        )
        threads.append(thread)
        thread.start()

    # 等待所有线程完成
    for thread in threads:
        thread.join()
    print()

    # 最终汇总
    print_yellow("\n" + "=" * 70)
    print_yellow(f"[+] 扫描完成 | 时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 新增：CDN模块汇总统计
    if scan_module == 'cdn':
        cdn_count = sum(
            1 for r in results if r['status'] == 'success' and r['data'].get('cdn_info', {}).get('is_cdn', False))
        print_yellow(f"[+] 检测结果：共发现 {cdn_count} 个CDN节点 | 总扫描IP：{total_ips} 个")

    elif scan_module == 'port_scan':
        total_open_ports = sum(len(r['data'].get('open_ports', [])) for r in results if r['status'] == 'success')
        affected_ips = sum(1 for r in results if r['status'] == 'success' and r['data'].get('total', 0) > 0)
        print_yellow(f"[+] 总开放端口: {total_open_ports} 个 | 涉及IP: {affected_ips} 个")

    elif scan_module == 'web_discovery':
        total_web = sum(len(r['data'].get('web_services', [])) for r in results if r['status'] == 'success')
        affected_ips = sum(1 for r in results if r['status'] == 'success' and r['data'].get('web_services', []))
        print_yellow(f"[+] 总Web服务: {total_web} 个 | 涉及IP: {affected_ips} 个")

    elif scan_module == 'full':
        total_web = sum(len(r['data'].get('web_services', [])) for r in results if r['status'] == 'success')
        total_ports = sum(len(r['data'].get('open_ports', [])) for r in results if r['status'] == 'success')
        cdn_count = sum(
            1 for r in results if r['status'] == 'success' and r['data'].get('cdn_info', {}).get('is_cdn', False))
        print_yellow(f"[+] 总Web服务: {total_web} 个 | 总开放端口: {total_ports} 个 | CDN节点: {cdn_count} 个")

    print_yellow("=" * 70)
