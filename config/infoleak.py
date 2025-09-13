import json
import threading
import requests
import re
from colorama import Fore, Style
from config.output import get_time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 忽略SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 全局配置
RESULT = []
THREAD_LOCK = threading.Lock()
THREAD_SEM = threading.Semaphore(20)  # 线程数控制


def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)


def print_yellow(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)


def load_payloads():
    """加载信息泄露检测Payload（从相对路径读取）"""
    try:
        # 建议将infoleak.json放在config/data目录下
        with open('config/data/infoleak.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data['data'][0] if 'data' in data else {}
    except FileNotFoundError:
        print_yellow("[!] 未找到payload文件: config/data/infoleak.json")
        return {}
    except json.JSONDecodeError:
        print_yellow("[!] infoleak.json格式错误")
        return {}


def check_leak(url, payload, leak_type):
    """检测单个URL+Payload是否存在信息泄露"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
        }
        response = requests.get(
            url,
            headers=headers,
            timeout=8,
            verify=False,
            allow_redirects=True
        )

        # 基础检测规则：状态码200 + 响应长度>0
        if response.status_code == 200 and len(response.content) > 0:
            # 进一步验证是否包含敏感特征（如备份文件、配置文件特征）
            sensitive_patterns = [
                r'root:', r'password', r'config', r'database',
                r'.sql', r'.bak', r'.zip', r'.log'
            ]
            content = response.text.lower()
            if any(re.search(p, content) for p in sensitive_patterns):
                with THREAD_LOCK:
                    RESULT.append({
                        'url': url,
                        'type': leak_type,
                        'status': response.status_code,
                        'length': len(response.content),
                        'time': get_time()
                    })
                return True
        return False
    except Exception as e:
        return False


def thread_worker(url, payload, leak_type):
    """线程工作函数"""
    try:
        if check_leak(url, payload, leak_type):
            print_green(f"[+] 发现信息泄露: {url} ({leak_type})")
    finally:
        THREAD_SEM.release()


def infoleak_scan(args):
    """信息泄露扫描主函数"""
    global RESULT
    RESULT = []
    url = args.url.strip()

    # 验证URL格式
    if not (url.startswith('http://') or url.startswith('https://')):
        print_yellow(f"[!] 无效URL: {url}（需以http://或https://开头）")
        return

    # 加载Payload
    payloads = load_payloads()
    if not payloads:
        return
    total = sum(len(p_list) for p_list in payloads.values())
    print_cyan(f"\n[+] 开始信息泄露扫描: {url} {get_time()}")
    print_cyan(f"[+] 加载Payload类型: {', '.join(payloads.keys())}")
    print_cyan(f"[+] 总检测点: {total} 个 | 线程数: {args.threads}")
    print_cyan("-" * 80)

    # 调整线程数
    THREAD_SEM._value = args.threads  # 更新信号量值
    threads = []

    # 生成任务并启动线程
    for leak_type, p_list in payloads.items():
        for payload in p_list:
            target_url = url.rstrip('/') + payload
            THREAD_SEM.acquire()
            th = threading.Thread(
                target=thread_worker,
                args=(target_url, payload, leak_type)
            )
            threads.append(th)
            th.start()

    # 等待所有线程完成
    for th in threads:
        th.join()

    # 输出结果
    print_cyan("\n" + "=" * 80)
    print_cyan(f"[+] 扫描完成 {get_time()}")
    print_cyan(f"[+] 总检测点: {total} 个 | 发现信息泄露: {len(RESULT)} 个")

    if RESULT:
        print_yellow("\n详细结果:")
        for i, res in enumerate(RESULT, 1):
            print(f"\n{i}. {res['url']}")
            print(f"   类型: {res['type']} | 状态码: {res['status']}")
            print(f"   长度: {res['length']} | 时间: {res['time']}")

    # 导出结果
    if args.output and RESULT:
        import csv
        output_path = args.output if args.output.endswith('.csv') else args.output + '.csv'
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['序号', 'URL', '类型', '状态码', '长度', '时间'])
            for i, res in enumerate(RESULT, 1):
                writer.writerow([i, res['url'], res['type'], res['status'], res['length'], res['time']])
        print_green(f"\n[+] 结果已导出至: {output_path}")

    print_cyan("\n" + "=" * 80)