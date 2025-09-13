import requests
import re
import time
from collections import deque
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 忽略SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 颜色输出函数（与项目统一）
def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)

def print_red(text):
    print(Fore.RED + text + Style.RESET_ALL)

def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)

def print_yellow(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


class APIFinder:
    def __init__(self, url, cookie=None, deep=False, recursive_depth=3, bruteforce=False, delay=0.5):
        self.url = url
        self.cookie = cookie
        self.deep = deep  # 深度模式
        self.recursive_depth = recursive_depth  # 递归深度
        self.bruteforce = bruteforce  # 路径爆破开关
        self.delay = delay  # 请求延迟
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Cookie": self.cookie if self.cookie else ""
        }
        self.found_urls = []  # 发现的URL
        self.found_subdomains = []  # 发现的子域名
        self.sensitive_info = []  # 敏感信息列表
        self.visited = set()  # 已访问URL集合

    # 1. 提取URL（核心正则）
    def extract_urls(self, content):
        pattern = re.compile(
            r"""(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}|(?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]]{1,}[^"'><,;|()]{1,}|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|)|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"|']{0,}|))(?:"|')""",
            re.VERBOSE
        )
        matches = pattern.findall(str(content))
        return [match.strip('"').strip("'") for match in matches]

    # 2. 获取页面内容
    def fetch_content(self, url):
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            response.raise_for_status()  # 抛出HTTP错误状态码
            return response.content.decode("utf-8", "ignore")
        except Exception as e:
            print_red(f"[!] 获取{url}失败: {str(e)}")
            return None

    # 3. 规范化URL（相对路径转绝对路径）
    def normalize_url(self, base_url, relative_url):
        if not relative_url:
            return None
        parsed_base = urlparse(base_url)
        base_scheme = parsed_base.scheme
        base_netloc = parsed_base.netloc

        if relative_url.startswith(("http://", "https://")):
            return relative_url
        elif relative_url.startswith("//"):
            return f"{base_scheme}:{relative_url}"
        elif relative_url.startswith("/"):
            return f"{base_scheme}://{base_netloc}{relative_url}"
        elif relative_url.startswith(("./", "../")):
            return f"{base_scheme}://{base_netloc}/{relative_url}"
        else:
            return f"{base_scheme}://{base_netloc}/{relative_url}"

    # 4. 敏感信息检测（核心增强功能）
    def detect_sensitive_info(self, url, content):
        # 排除静态资源
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp',
                         '.tif', '.tiff', '.webp', '.woff', '.woff2', '.ttf', '.eot', '.otf',
                         '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.pdf', '.doc',
                         '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        exclude_paths = ['/static/', '/public/', '/assets/', '/cdn/', '/dist/', '/build/', '/media/', '/uploads/']
        parsed = urlparse(url)
        path = parsed.path.lower()

        # 过滤静态资源
        if any(path.endswith(ext) for ext in static_extensions) or any(p in path for p in exclude_paths):
            return []

        # 敏感信息模式匹配
        patterns = {
            # 文件下载接口检测
            'download': re.compile(r'(download|dload|down|dl\b|getfile|fileget|fileDownload|export)(/[^/]*)?$',
                                   re.IGNORECASE),
            # 文件上传接口检测
            'upload': re.compile(r'(upload|up\b|import|filepost|filePush|fileput|attachment)(/[^/]*)?$', re.IGNORECASE),
            # 密钥信息检测
            'secret': re.compile(r'secret|key|password|pwd|passwd|credential|token|auth|private', re.IGNORECASE),
            # 备份文件检测
            'backup': re.compile(r'backup|bak|dump|archive', re.IGNORECASE),
            # 配置文件检测
            'config': re.compile(r'config|cfg|setting|conf', re.IGNORECASE),
            # 数据库相关 - 更精确的匹配，要求是独立的单词或者出现在路径中
            'database': re.compile(r'(^|/)(db|database|sql|mongo|redis|es)($|/)', re.IGNORECASE),
            # 管理员接口
            'admin': re.compile(r'(^|/)(admin|manage|super|root|controller)($|/)', re.IGNORECASE),
            # 新增敏感信息检测
            'aes_key': re.compile(r'aes[_-]?key[=:]\s*[\'"]([a-f0-9]{16,64})[\'"]', re.IGNORECASE),
            'aes_iv': re.compile(r'aes[_-]?iv[=:]\s*[\'"]([a-f0-9]{8,32})[\'"]', re.IGNORECASE),
            'swagger': re.compile(r'swagger-ui|swagger\.json|/v2/api-docs', re.IGNORECASE),
            'spring_boot': re.compile(r'/actuator|/heapdump|/env|/metrics|/trace', re.IGNORECASE),
            'app_credentials': re.compile(r'(app(lication)?[_-]?(id|secret|key)[=:]\s*[\'"]([a-f0-9]{8,64})[\'"])',
                                          re.IGNORECASE),
            'cloud_key': re.compile(
                r'(aliyun|tencent|aws|azure|gcp)[_-]?(access|secret)[_-]?key[=:]\s*[\'"]([a-f0-9]{20,60})[\'"]',
                re.IGNORECASE),
            'phone_number': re.compile(r'1[3-9]\d{9}'),
            'credentials': re.compile(
                r'(username|user|u)[=:]\s*[\'"]([^\'"]+)[\'"][\s,;]*(password|pass|pwd)[=:]\s*[\'"]([^\'"]+)[\'"]'),
            'druid': re.compile(r'druid/index.html', re.IGNORECASE),
            'prometheus': re.compile(r'/metrics|/prometheus', re.IGNORECASE),
            'docker': re.compile(r'/containers/json|/images/json', re.IGNORECASE),
            'graphql': re.compile(r'graphql', re.IGNORECASE),
            'jdbc': re.compile(r'jdbc:(mysql|postgresql|sqlserver):', re.IGNORECASE),
            'elasticsearch': re.compile(r'_search\?|/_cat', re.IGNORECASE),
            'api_key': re.compile(r'(?:api[_-]?key|access[_-]?token|secret[_-]?key)[=:]\s*[\'"]([a-f0-9]{32,64})[\'"]',
                                  re.IGNORECASE),
            'oauth': re.compile(r'(client[_-]?(id|secret)|redirect[_-]?uri)[=:]\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
        }

        sensitive_types = []
        # 从URL检测
        for key, pattern in patterns.items():
            if pattern.search(url):
                sensitive_types.append(key)

        # 从内容检测
        if content:
            if 'swagger-ui' in content.lower() or '/v2/api-docs' in content.lower():
                sensitive_types.append('swagger')
            if 'spring boot' in content.lower() or '/actuator' in url:
                sensitive_types.append('spring_boot')
                # 检测密钥格式
            if re.search(r'api[_-]?key', content.lower()) or \
                    re.search(r'password\s*[=:]\s*[\'"]?[a-z0-9]{12,}[\'"]?', content.lower()) or \
                    re.search(r'secret\s*[=:]\s*[\'"]?[a-z0-9]{12,}[\'"]?', content.lower()):
                sensitive_types.append('secret')
            # 检测文件下载链接
            if re.search(r'href=[\'"][^\'"]*\.(zip|tar|gz|rar|sql|bak|db|dump)[\'"]', content.lower()):
                sensitive_types.append('download')
                sensitive_types.append('backup')

        return list(set(sensitive_types))  # 去重

    # 5. 路径爆破（基于已知路径推测）
    def path_bruteforce(self, base_url):
        parsed = urlparse(base_url)
        base_netloc = parsed.netloc
        # 从已发现URL提取路径片段
        path_segments = set()
        for url in self.found_urls:
            path = urlparse(url).path
            path_segments.update([seg for seg in path.split('/') if seg and len(seg) > 2])

        # 常见接口模式与端点
        common_patterns = [
        "/{base}/v1/{ep}",
        "/api/{base}/{ep}",
        "/{base}/api/{ep}",
        "/{base}/v1/api/{ep}",
        "/gateway/{base}/{ep}",
        "/{base}-api/{ep}",
        "/{base}/service/{ep}"
        ]
        common_endpoints = ["user", "login", "auth", "token", "config",
        "setting", "info", "data", "list", "detail",
        "create", "update", "delete", "export", "import",
        "search", "query", "mobile", "phone", "verify"]

        # 生成推测路径
        generated_paths = set()
        for seg in path_segments:
            for pattern in common_patterns:
                for ep in common_endpoints:
                    generated_path = pattern.format(base=seg, ep=ep)
                    generated_paths.add(generated_path)

        # 验证推测路径
        valid_paths = []
        for path in generated_paths:
            test_url = f"{parsed.scheme}://{base_netloc}{path}"
            if test_url in self.visited:
                continue
            try:
                time.sleep(self.delay)
                response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                if response.status_code < 400:  # 200-399视为有效
                    valid_paths.append(test_url)
                    print_green(f"[+] 爆破发现有效路径: {test_url} ({response.status_code})")
                    # 检测敏感信息
                    sensitive = self.detect_sensitive_info(test_url, response.text)
                    if sensitive:
                        self.sensitive_info.append((test_url, sensitive))
            except:
                continue

        return valid_paths

    # 6. Webpack模块解析
    def extract_webpack_modules(self, js_content):
        if "webpack" not in js_content.lower():
            return []
        # 匹配Webpack模块
        module_pattern = re.compile(
            r"\d+:\s*function\s*\(\w+,\s*\w+,\s*\w+\)\s*{\s*(.*?)\s*}", re.DOTALL
        )
        modules = module_pattern.findall(js_content)
        # 提取模块中的字符串
        strings = []
        for module in modules:
            if len(module) < 20:
                continue
            # 匹配字符串
            str_pattern = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', re.DOTALL)
            module_strings = str_pattern.findall(module)
            strings.extend([s[1:-1] for s in module_strings if len(s) > 5])
        return strings

    # 7. 递归爬取（深度模式核心）
    def recursive_crawl(self, url, current_depth):
        if current_depth > self.recursive_depth or url in self.visited:
            return
        self.visited.add(url)
        print_cyan(f"[*] 递归爬取（深度{current_depth}）: {url}")

        # 获取页面内容
        content = self.fetch_content(url)
        if not content:
            return

        # 提取URL
        raw_urls = self.extract_urls(content)
        normalized_urls = [self.normalize_url(url, u) for u in raw_urls if u]
        for u in normalized_urls:
            if u and u not in self.found_urls:
                self.found_urls.append(u)

        # 检测敏感信息
        sensitive = self.detect_sensitive_info(url, content)
        if sensitive:
            self.sensitive_info.append((url, sensitive))
            print_yellow(f"[!] 发现敏感信息: {', '.join(sensitive)} | {url}")

        # 提取页面中的链接（用于递归）
        soup = BeautifulSoup(content, "html.parser")
        links = []
        for tag in soup.find_all(['a', 'img', 'script', 'link']):
            attr = 'href' if tag.name in ['a', 'link'] else 'src'
            link = tag.get(attr)
            if link and not link.startswith(('javascript:', 'mailto:', 'tel:')):
                links.append(link)

        # 处理链接并递归
        for link in links:
            abs_link = urljoin(url, link)
            if abs_link not in self.visited:
                time.sleep(self.delay)
                self.recursive_crawl(abs_link, current_depth + 1)

        # 处理JS文件中的Webpack模块
        if url.endswith('.js') and "webpack" in content.lower():
            webpack_strings = self.extract_webpack_modules(content)
            if webpack_strings:
                print_green(f"[+] 解析到Webpack模块，提取{len(webpack_strings)}个字符串")
                # 从Webpack字符串中再提取URL
                for s in webpack_strings:
                    js_urls = self.extract_urls(s)
                    for u in js_urls:
                        normalized = self.normalize_url(url, u)
                        if normalized and normalized not in self.found_urls:
                            self.found_urls.append(normalized)

    # 8. 提取子域名
    def extract_subdomains(self):
        parsed_base = urlparse(self.url)
        base_domain = parsed_base.netloc.split(":")[0]
        parts = base_domain.split(".")
        main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else base_domain

        subdomains = []
        for url in self.found_urls:
            parsed = urlparse(url)
            subdomain = parsed.netloc.split(":")[0]
            if subdomain and main_domain in subdomain and subdomain not in subdomains:
                subdomains.append(subdomain)
        self.found_subdomains = subdomains

    # 9. 运行主逻辑
    def run(self):
        print_cyan("\n" + "="*80)
        print_cyan("          APIFinder 扫描开始          ")
        print_cyan("="*80)

        # 初始化URL
        self.found_urls.append(self.url)
        self.visited.add(self.url)

        # 执行扫描
        if self.deep:
            self.recursive_crawl(self.url, 1)
        else:
            # 简单模式：仅扫描当前页面
            content = self.fetch_content(self.url)
            if content:
                raw_urls = self.extract_urls(content)
                self.found_urls = [self.normalize_url(self.url, u) for u in raw_urls if u]
                # 检测敏感信息
                sensitive = self.detect_sensitive_info(self.url, content)
                if sensitive:
                    self.sensitive_info.append((self.url, sensitive))

        # 路径爆破（如果启用）
        if self.bruteforce:
            print_cyan("\n[*] 开始路径爆破...")
            brute_urls = self.path_bruteforce(self.url)
            self.found_urls.extend(brute_urls)

        # 提取子域名
        self.extract_subdomains()

        # 显示结果
        self.display_results()

    # 10. 显示结果
    def display_results(self):
        print_cyan("\n" + "="*80)
        print_cyan("          APIFinder 扫描结果          ")
        print_cyan("="*80)

        # 显示URL
        if self.found_urls:
            print_green(f"[+] 共发现{len(self.found_urls)}个URL:")
            for i, url in enumerate(self.found_urls[:50], 1):  # 限制显示前50个
                print(f"{i}. {url}")
            if len(self.found_urls) > 50:
                print_yellow(f"[!] 省略显示{len(self.found_urls)-50}个URL")

        # 显示子域名
        if self.found_subdomains:
            print_green(f"\n[+] 共发现{len(self.found_subdomains)}个子域名:")
            for i, sub in enumerate(self.found_subdomains, 1):
                print(f"{i}. {sub}")

        # 显示敏感信息
        if self.sensitive_info:
            print_red(f"\n[!] 共发现{len(self.sensitive_info)}处敏感信息:")
            for i, (url, types) in enumerate(self.sensitive_info, 1):
                print(f"{i}. [{', '.join(types)}] {url}")

        print_cyan("\n" + "="*80)


# 扫描入口函数
def run_apifinder(args):
    """APIFinder扫描入口"""
    print_cyan("\n" + "="*80)
    print_cyan("          APIFinder模块          ")
    print_cyan("="*80)

    # 1. 选择扫描模式（简单/深度）
    print_cyan("\n请选择扫描模式：")
    print("1. 简单模式（仅当前页面及JS）")
    print("2. 深度模式（递归爬取链接）")
    while True:
        mode_choice = input("请输入选项（1-2）: ").strip()
        if mode_choice in ['1', '2']:
            deep_mode = (mode_choice == '2')
            break
        else:
            print_red("无效选项，请输入1或2！")

    # 2. 设置递归深度（仅深度模式）
    recursive_depth = 3
    if deep_mode:
        while True:
            depth_input = input("\n请设置递归深度（1-5，默认3）: ").strip()
            if not depth_input:
                break
            if depth_input.isdigit() and 1 <= int(depth_input) <= 5:
                recursive_depth = int(depth_input)
                break
            else:
                print_red("无效输入，请输入1-5之间的数字！")

    # 3. 启用路径爆破
    bruteforce = False
    while True:
        brute_choice = input("\n是否启用路径爆破？(y/N): ").strip().lower()
        if brute_choice in ['y', 'yes']:
            bruteforce = True
            break
        elif brute_choice in ['n', 'no', '']:
            break
        else:
            print_red("无效输入，请输入y或n！")

    # 4. 设置请求延迟
    delay = 0.5
    while True:
        delay_input = input("\n请设置请求延迟（秒，默认0.5）: ").strip()
        if not delay_input:
            break
        try:
            delay = float(delay_input)
            if delay >= 0:
                break
            else:
                print_red("延迟不能为负数！")
        except ValueError:
            print_red("无效输入，请输入数字！")

    # 5. 设置Cookie
    cookie = None
    while True:
        cookie_choice = input("\n是否需要设置Cookie？(y/N): ").strip().lower()
        if cookie_choice in ['y', 'yes']:
            cookie = input("请输入Cookie内容: ").strip()
            break
        elif cookie_choice in ['n', 'no', '']:
            break
        else:
            print_red("无效输入，请输入y或n！")

    # 6. 执行扫描
    api_finder = APIFinder(
        url=args.url,
        cookie=cookie,
        deep=deep_mode,
        recursive_depth=recursive_depth,
        bruteforce=bruteforce,
        delay=delay
    )
    api_finder.run()


# 主函数入口（供主程序调用）
def main(args):
    run_apifinder(args)