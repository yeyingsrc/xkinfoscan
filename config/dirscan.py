import random
import colorama
import requests
import threading
import time
import csv
from urllib.parse import urlparse, urlunparse
from config.output import get_time

# 初始化颜色支持
colorama.init(autoreset=True)


def dirxkscan(args):
    # 可用扫描模块列表
    modules = {
        '小模块': [
            'shell', 'dir', 'asp', 'aspx', 'php',
            'py', 'sql', 'pl', 'cgi', 'cfm',
            'thinkphp', 'jsp', 'mdb', 'fck', 'springboot',
            'backup', 'tophigh', 'wordpress', 'phpmyadmin', 'phpcms',
            'discuz', 'dedecms', 'ecshop', 'ewebeditor', 'empire'
        ],
        '大模块': [
            'mdir', 'masp', 'maspx', 'mjsp', 'mmdb',
            'mfck', 'mphp'
        ]
    }

    # 模块与字典文件映射
    dict_mapping = {
        # 小模块
        'shell': 'config/dic/SHELL.txt', 'dir': 'config/dic/DIR.txt', 'asp': 'config/dic/ASP.txt',
        'aspx': 'config/dic/ASPX.txt', 'php': 'config/dic/PHP.txt', 'py': 'config/dic/PY.txt',
        'sql': 'config/dic/SQL.txt', 'pl': 'config/dic/PL.txt', 'cgi': 'config/dic/CGI.txt',
        'cfm': 'config/dic/CFM.txt', 'thinkphp': 'config/dic/THINKPHP.txt', 'jsp': 'config/dic/JSP.txt',
        'mdb': 'config/dic/MDB.txt', 'fck': 'config/dic/FCK.txt', 'springboot': 'config/dic/SPRINGBOOT.txt',
        'backup': 'config/dic/BACKUP.txt', 'tophigh': 'config/dic/TOPHIGH.txt', 'wordpress': 'config/dic/WORDPRESS3.5.txt',
        'phpmyadmin': 'config/dic/PHPMYADMIN.txt', 'phpcms': 'config/dic/PHPCMS9.5.7.txt', 'discuz': 'config/dic/DISCUZ3.1.txt',
        'dedecms': 'config/dic/DEDECMSV5.7.txt', 'ecshop': 'config/dic/ECSHOPV2.7.2.txt', 'ewebeditor': 'config/dic/EWEBEDITOR.txt',
        'empire': 'config/dic/EMPIRE.txt',
        # 大模块
        'mdir': 'config/dic/max/MDIR.txt', 'masp': 'config/dic/max/MASP.txt', 'maspx': 'config/dic/max/MASPX.txt',
        'mjsp': 'config/dic/max/MJSP.txt', 'mmdb': 'config/dic/max/MMDB.txt', 'mfck': 'config/dic/max/MFCK.txt',
        'mphp': 'config/dic/max/MPHP.txt'
    }

    # 显示模块选择提示
    print("\n" + colorama.Fore.CYAN + "=" * 80)
    print("请输入扫描模块，可选择的模块如下：")

    # 打印小模块
    print(f"\n{colorama.Fore.YELLOW}[小模块] (适合快速扫描)")
    small_modules = modules['小模块']
    for i in range(0, len(small_modules), 5):
        row = small_modules[i:i + 5]
        print("  " + " | ".join(f"{m.ljust(12)}" for m in row))

    # 打印大模块
    print(f"\n{colorama.Fore.RED}[大模块] (包含大量字典，扫描较慢)")
    large_modules = modules['大模块']
    for i in range(0, len(large_modules), 5):
        row = large_modules[i:i + 5]
        print("  " + " | ".join(f"{m.ljust(12)}" for m in row))

    # 获取用户输入的模块
    default_module = 'tophigh'
    while True:
        module_input = input(f"\n请输入要使用的扫描模块（默认使用 {default_module}）: ").strip().lower()
        if not module_input:
            module = default_module
            break
        if module_input in dict_mapping:
            module = module_input
            break
        print(colorama.Fore.RED + f"无效的模块: {module_input}，请从上面的列表中选择")

    # ====================== 请求方法选择（与POC模块风格一致） ======================
    # 定义请求方法映射（序号: [方法名, 描述]）
    method_modules = {
        '1': ['get', 'GET请求（默认，适合大多数路径检测）'],
        '2': ['head', 'HEAD请求（仅获取响应头，速度快，隐蔽性高）'],
        '3': ['post', 'POST请求（适合表单提交类路径或需提交数据的场景）']
    }

    # 优先使用命令行参数，无参数则交互式选择
    req_method = args.method  # 从命令行获取
    if req_method not in ['get', 'head', 'post']:
        print("\n" + colorama.Fore.CYAN + "=" * 80)
        print("请选择请求方法：")
        # 打印方法列表（与POC子模块格式一致）
        for num, (method, desc) in method_modules.items():
            print(f"{num}. {colorama.Fore.GREEN}{method.ljust(10)} - {desc}")

        # 交互式输入验证
        while True:
            method_choice = input("\n请输入方法选项（1-3）: ").strip()
            if method_choice in method_modules:
                req_method = method_modules[method_choice][0]
                break
            else:
                print(colorama.Fore.RED + "无效选项，请输入1-3！")
    # 显示选择结果
    print(f"\n{colorama.Fore.CYAN}[+] 已选择请求方法: {req_method}（{dict(method_modules.values())[req_method]}）")
    # ===========================================================================

    # 读取User-Agent列表
    try:
        with open('config/user-agents.txt', 'r') as f:
            useragents = f.readlines()
        random_useragent = random.choice(useragents).strip()
    except FileNotFoundError:
        print(colorama.Fore.RED + "[!] 缺少user-agents.txt文件，使用默认UA" + colorama.Style.RESET_ALL)
        random_useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

    # 请求头设置
    base_headers = {'user-agent': random_useragent}
    bypass_headers = base_headers.copy()
    bypass_headers['X-Forwarded-For'] = '127.0.0.1'

    # 结果存储与锁
    results = []
    result_lock = threading.Lock()
    found_count = 0  # 已发现结果计数

    def check_directory(base_url, directory):
        nonlocal found_count
        try:
            # 解析基础URL
            parsed_url = urlparse(base_url)

            # 处理目录：强制去除前导斜杠
            clean_directory = directory.lstrip('/')

            # 拼接路径
            base_path = parsed_url.path.rstrip('/')
            if base_path:
                target_path = f"{base_path}/{clean_directory}"
            else:
                target_path = f"/{clean_directory}"

            # 构建完整目标URL
            target_url = urlunparse(parsed_url._replace(path=target_path))

            # 发送请求（使用选择的请求方法）
            if req_method == 'head':
                req = requests.head(target_url, headers=base_headers, timeout=5, allow_redirects=False)
            elif req_method == 'post':
                req = requests.post(target_url, headers=base_headers, timeout=5, allow_redirects=False)
            else:  # get
                req = requests.get(target_url, headers=base_headers, timeout=5, allow_redirects=False)

            # 处理401/403状态码
            bypass_used = False
            if req.status_code in (401, 403):
                if req_method == 'head':
                    req = requests.head(target_url, headers=bypass_headers, timeout=5, allow_redirects=False)
                elif req_method == 'post':
                    req = requests.post(target_url, headers=bypass_headers, timeout=5, allow_redirects=False)
                else:
                    req = requests.get(target_url, headers=bypass_headers, timeout=5, allow_redirects=False)
                bypass_used = True

            # 检查有价值的状态码并输出
            if req.status_code in (200, 302, 401, 403):
                with result_lock:
                    found_count += 1
                    status_color = {
                        200: colorama.Fore.GREEN,
                        302: colorama.Fore.BLUE,
                        401: colorama.Fore.YELLOW,
                        403: colorama.Fore.RED
                    }.get(req.status_code, colorama.Fore.WHITE)

                    results.append({
                        'url': req.url,
                        'status': req.status_code,
                        'length': len(req.content),
                        'bypass_used': bypass_used,
                        'time': get_time()
                    })

                    print(
                        f"\n{status_color}[+] 发现 #{found_count}: {req.url} (状态码: {req.status_code}) {get_time()}")
                    if bypass_used:
                        print(colorama.Fore.CYAN + "    [*] 使用X-Forwarded-For绕过成功")

                    update_progress()

        except Exception as e:
            pass

    # 处理目标URL（标准化）
    url = args.url.strip()
    original_url = url
    parsed = urlparse(url)
    normalized_path = parsed.path.replace('//', '/').rstrip('/')
    normalized_url = urlunparse(parsed._replace(path=normalized_path))
    url = normalized_url
    if original_url != url:
        print(colorama.Fore.CYAN + f"[*] 自动标准化URL：{original_url} -> {url}")

    # 加载字典并清洗目录
    try:
        with open(dict_mapping[module], 'r', encoding='gbk', errors='ignore') as f:
            wordlist = [line.strip().lstrip('/') for line in f.readlines() if line.strip()]
        total = len(wordlist)
        print(colorama.Fore.CYAN + f"\n[+] 已加载模块: {module}，字典条目数量: {total}（已自动清洗前导斜杠）")
        print(f"[+] 开始扫描目标: {url} {get_time()}")
        print(f"[+] 使用请求方法: {req_method}")  # 显示当前使用的请求方法
        print("-" * 80)
    except FileNotFoundError:
        print(colorama.Fore.RED + f"[!] 模块字典缺失: {dict_mapping[module]}" + colorama.Style.RESET_ALL)
        return

    # 进度控制
    progress = 0
    progress_lock = threading.Lock()

    def update_progress():
        with progress_lock:
            bar_length = 50
            filled = int(progress * bar_length // total)
            bar = '#' * filled + '-' * (bar_length - filled)
            percent = (progress / total) * 100
            print(f"\r进度: [{bar}] {progress}/{total} ({percent:.1f}%) 已发现: {found_count}", end='', flush=True)

    # 初始化进度条
    update_progress()

    # 多线程扫描
    threads = []
    for directory in wordlist:
        while threading.active_count() > args.threads:
            time.sleep(0.1)

        thread = threading.Thread(target=check_directory, args=(url, directory))
        threads.append(thread)
        thread.start()

        with progress_lock:
            progress += 1
        update_progress()

    # 等待所有线程完成
    for thread in threads:
        thread.join()
    print()  # 完成后换行

    # 最终结果展示
    print("\n" + colorama.Fore.CYAN + "=" * 80)
    print(f"[+] 扫描完成 {get_time()}")
    print(f"[+] 总扫描条目: {total} 条，发现有效结果: {len(results)} 条")
    print(f"[+] 使用的请求方法: {req_method}")  # 结果中显示请求方法

    if results and not args.output:
        print("\n" + colorama.Fore.YELLOW + "详细结果:")
        for i, res in enumerate(results, 1):
            status_color = {
                200: colorama.Fore.GREEN,
                302: colorama.Fore.BLUE,
                401: colorama.Fore.YELLOW,
                403: colorama.Fore.RED
            }.get(res['status'], colorama.Fore.WHITE)

            print(f"\n{i}. {status_color}{res['url']}")
            print(f"   状态码: {res['status']} | 长度: {res['length']} | 时间: {res['time']}")
            if res['bypass_used']:
                print(f"   备注: 使用X-Forwarded-For绕过成功")

    # 导出结果（仅支持CSV格式）
    if args.output:
        output_path = args.output
        # 确保输出路径以.csv结尾
        if not output_path.endswith('.csv'):
            output_path += '.csv'

        # 导出为CSV格式（Excel可直接打开）
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # 写入表头（增加请求方法列）
            writer.writerow(['序号', 'URL', '状态码', '内容长度', '发现时间', '是否使用绕过', '请求方法'])
            # 写入数据
            for i, res in enumerate(results, 1):
                writer.writerow([
                    i,
                    res['url'],
                    res['status'],
                    res['length'],
                    res['time'],
                    '是' if res['bypass_used'] else '否',
                    req_method  # 记录当前使用的请求方法
                ])
        print(colorama.Fore.GREEN + f"\n[+] CSV结果已导出至: {output_path}（可直接用Excel打开）")

    print("\n" + colorama.Fore.CYAN + "=" * 80)