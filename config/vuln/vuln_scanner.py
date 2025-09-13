import requests
from colorama import Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 忽略SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)

def print_red(text):
    print(Fore.RED + text + Style.RESET_ALL)

def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)
# 主扫描函数
def run_vuln_scan(args, vuln_type, mode):
    """常规漏洞扫描入口"""
    url = args.url
    results = []

    # 新增：未授权访问漏洞扫描分支
    if vuln_type in ['unauthorized', 'all']:
        from config.vuln.unauthorized import run_unauthorized_scan
        run_unauthorized_scan(args)
        # 如果只扫描未授权漏洞，直接返回
        if vuln_type == 'unauthorized':
            return
        # 2. 弱密码检测（新增子模块）
        # 新增：弱密码扫描分支
    if vuln_type in ['weakpass', 'all']:
        from config.vuln.weakcheck import run_weakcheck_scan
        run_weakcheck_scan(args)
        # 如果只扫描弱密码，直接返回
        if vuln_type == 'weakpass':
            return
    # 输出结果
    print_cyan("\n" + "=" * 80)
    print_green(f"[+] 常规漏洞扫描完成 | 漏洞类型: {vuln_type} | 模式: {mode}")
    if results:
        print_red(f"[!] 共发现 {len(results)} 个可疑漏洞点：")
        for i, res in enumerate(results, 1):
            print(f"\n{i}. URL: {res.get('url', url)}")
            print(f"   状态: {res.get('status')}")
            if 'payload' in res:
                print(f"   触发Payload: {res['payload']}")
    else:
        print_green("[+] 未发现明显漏洞")
    print_cyan("=" * 80)

    # 结果导出
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(f"常规漏洞扫描结果（{vuln_type} | {mode}）\n")
            f.write(f"目标URL: {url}\n")
            for res in results:
                f.write(f"{res}\n")
        print_green(f"\n[+] 结果已导出至: {args.output}")