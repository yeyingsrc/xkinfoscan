import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style
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


class JSFinder:
    def __init__(self, url, cookie=None, deep=False):
        self.url = url
        self.cookie = cookie
        self.deep = deep  # 深度模式标志
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Cookie": self.cookie if self.cookie else ""
        }
        self.found_urls = []  # 存储发现的URL
        self.found_subdomains = []  # 存储发现的子域名

    # 核心正则：提取URL（来自原代码优化）
    def extract_urls(self, content):
        pattern = re.compile(
            r"""(?:"|')((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}|(?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]]{1,}[^"'><,;|()]{1,}|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|)|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"|']{0,}|))(?:"|')""",
            re.VERBOSE
        )
        matches = pattern.findall(str(content))
        return [match.strip('"').strip("'") for match in matches]

    # 获取页面内容
    def fetch_content(self, url):
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            return response.content.decode("utf-8", "ignore")
        except Exception as e:
            print_red(f"[!] 获取{url}内容失败: {str(e)}")
            return None

    # 处理相对URL为绝对URL
    def normalize_url(self, base_url, relative_url):
        if not relative_url:
            return None
        parsed_base = urlparse(base_url)
        base_scheme = parsed_base.scheme
        base_netloc = parsed_base.netloc

        # 处理不同类型的URL
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

    # 从HTML中提取JS文件URL
    def extract_js_files(self, html_content, base_url):
        js_urls = []
        if not html_content:
            return js_urls
        soup = BeautifulSoup(html_content, "html.parser")
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                normalized = self.normalize_url(base_url, src)
                if normalized and normalized not in js_urls:
                    js_urls.append(normalized)
        return js_urls

    # 提取子域名
    def extract_subdomains(self, urls):
        subdomains = []
        parsed_base = urlparse(self.url)
        base_domain = parsed_base.netloc.split(":")[0]  # 去除端口
        # 提取主域名（如从www.baidu.com提取baidu.com）
        parts = base_domain.split(".")
        main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else base_domain

        for url in urls:
            parsed = urlparse(url)
            subdomain = parsed.netloc.split(":")[0]  # 去除端口
            if subdomain and main_domain in subdomain and subdomain not in subdomains:
                subdomains.append(subdomain)
        return subdomains

    # 简单模式：仅扫描当前页面及关联JS
    def simple_scan(self):
        print_cyan(f"[+] 开始简单模式扫描 | 目标: {self.url}")
        # 1. 获取页面HTML
        html_content = self.fetch_content(self.url)
        if not html_content:
            return
        # 2. 提取页面中的URL
        page_urls = self.extract_urls(html_content)
        normalized_page_urls = [self.normalize_url(self.url, u) for u in page_urls if u]

        # 3. 提取页面中的JS文件并解析
        js_files = self.extract_js_files(html_content, self.url)
        print_green(f"[+] 发现{len(js_files)}个JS文件，开始提取URL...")
        js_urls = []
        for js_url in js_files:
            js_content = self.fetch_content(js_url)
            if js_content:
                extracted = self.extract_urls(js_content)
                normalized = [self.normalize_url(js_url, u) for u in extracted if u]
                js_urls.extend(normalized)

        # 合并去重
        all_urls = list(set(normalized_page_urls + js_urls))
        self.found_urls = [u for u in all_urls if u]

    # 深度模式：递归扫描页面链接
    def deep_scan(self, max_depth=2, current_depth=1, visited=None):
        if visited is None:
            visited = set()
        # 避免重复访问和过深递归
        if self.url in visited or current_depth > max_depth:
            return
        visited.add(self.url)
        print_cyan(f"[+] 深度模式（层级{current_depth}）扫描 | 目标: {self.url}")

        # 1. 执行简单扫描逻辑
        html_content = self.fetch_content(self.url)
        if not html_content:
            return
        page_urls = self.extract_urls(html_content)
        normalized_page_urls = [self.normalize_url(self.url, u) for u in page_urls if u]

        js_files = self.extract_js_files(html_content, self.url)
        js_urls = []
        for js_url in js_files:
            js_content = self.fetch_content(js_url)
            if js_content:
                extracted = self.extract_urls(js_content)
                normalized = [self.normalize_url(js_url, u) for u in extracted if u]
                js_urls.extend(normalized)

        # 2. 提取页面中的链接用于递归
        soup = BeautifulSoup(html_content, "html.parser")
        links = []
        for a in soup.find_all("a"):
            href = a.get("href")
            if href:
                normalized = self.normalize_url(self.url, href)
                if normalized and normalized not in visited:
                    links.append(normalized)

        # 3. 合并URL
        all_urls = list(set(normalized_page_urls + js_urls))
        self.found_urls.extend([u for u in all_urls if u and u not in self.found_urls])

        # 4. 递归扫描链接
        print_green(f"[+] 发现{len(links)}个页面链接，准备递归扫描...")
        for link in links:
            self.url = link  # 临时切换目标URL
            self.deep_scan(max_depth, current_depth + 1, visited)

    # 运行扫描
    def run(self):
        if self.deep:
            self.deep_scan()
        else:
            self.simple_scan()

        # 提取子域名
        self.found_subdomains = self.extract_subdomains(self.found_urls)
        self.display_results()

    # 显示结果
    def display_results(self):
        print_cyan("\n" + "=" * 80)
        print_cyan("          JS信息提取结果          ")
        print_cyan("=" * 80)

        # 显示URL
        if self.found_urls:
            print_green(f"[+] 共发现{len(self.found_urls)}个URL:")
            for i, url in enumerate(self.found_urls[:50], 1):  # 限制显示前50个
                print(f"{i}. {url}")
            if len(self.found_urls) > 50:
                print(f"[!] 省略显示{len(self.found_urls) - 50}个URL")

        # 显示子域名
        if self.found_subdomains:
            print_green(f"\n[+] 共发现{len(self.found_subdomains)}个子域名:")
            for i, subdomain in enumerate(self.found_subdomains, 1):
                print(f"{i}. {subdomain}")

        print_cyan("\n" + "=" * 80)


# 扫描入口函数
def run_jsfinder(args):
    """JSFinder扫描入口"""
    print_cyan("\n" + "=" * 80)
    print_cyan("          JSFinder模块          ")
    print_cyan("=" * 80)

    # 1. 选择扫描模式
    print_cyan("\n请选择扫描模式：")
    print("1. 简单模式（仅当前页面及关联JS）")
    print("2. 深度模式（递归扫描页面链接，最多2层）")
    while True:
        choice = input("请输入选项（1-2）: ").strip()
        if choice in ['1', '2']:
            deep_mode = (choice == '2')
            break
        else:
            print_red("无效选项，请输入1或2！")

    # 2. 询问是否需要设置Cookie
    cookie = None
    while True:
        use_cookie = input("\n是否需要设置Cookie？(y/N): ").strip().lower()
        if use_cookie in ['y', 'yes']:
            cookie = input("请输入Cookie内容: ").strip()
            break
        elif use_cookie in ['n', 'no', '']:
            break
        else:
            print_red("无效输入，请输入y或n！")

    # 3. 执行扫描
    js_finder = JSFinder(
        url=args.url,
        cookie=cookie,
        deep=deep_mode
    )
    js_finder.run()