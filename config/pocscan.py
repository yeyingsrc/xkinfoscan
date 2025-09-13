import os
import importlib
import requests
from colorama import Fore, Style
from datetime import datetime

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()


def poc_scan(args, poc_mode):
    """POC盲打扫描主函数（接收主程序传递的poc_mode参数）"""
    # header = {
    #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'
    # }

    # 处理目标URL
    url = args.url.strip()
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"

    # 显示当前扫描信息
    print(Fore.CYAN + f"\n[+] 开始对目标 {url} 进行POC盲打扫描")
    print(Fore.CYAN + f"[+] 选中子模块: {poc_mode}（{get_poc_mode_desc(poc_mode)}）")
    print("-" * 80)

    try:
        # 根据选择的子模式加载POC模块
        poc_module_list = get_poc_module_list(poc_mode)
        if not poc_module_list:
            print(Fore.RED + "[!] 未加载到任何POC模块，请检查sword目录是否存在")
            return

        # 执行POC验证
        target_list = [url]
        results = verify(target_list, poc_module_list)

        # 输出扫描结果
        print("\n" + Fore.GREEN + "=" * 80)
        print(f"[+] POC盲打扫描完成，共检测 {len(poc_module_list)} 个POC")
        print("-" * 80)
        for result in results:
            if result['vulnerable']:
                print(f"{Fore.RED}[!] 存在漏洞: {result['name']}")
                print(f"    目标: {result['target']}")
                if result.get('details'):
                    print(f"    详情: {result['details']}")
            else:
                print(f"{Fore.GREEN}[+] 无漏洞: {result['name']}")
        print(Fore.GREEN + "=" * 80)

        # 导出结果到CSV
        if args.output:
            export_poc_result(args.output, url, poc_mode, results)

    except Exception as e:
        print(Fore.RED + f"\n[!] 扫描过程出错: {str(e)}")


def get_poc_mode_desc(mode):
    """获取POC模式的描述信息"""
    desc_map = {
        'web': 'Web应用漏洞（如SQL注入、XSS、文件上传等）',
        'framework': '开发框架漏洞（如Struts2、Spring、ThinkPHP等）',
        'middleware': '中间件漏洞（如Tomcat、Nginx、Apache等）',
        'port': '端口服务漏洞（如Redis、MySQL、MongoDB等）'
    }
    return desc_map.get(mode, "未知模式")


def get_dir_files(base_path):
    """递归获取目录下所有Python文件（POC模块）"""
    file_list = []
    if os.path.isdir(base_path):
        for entry in os.listdir(base_path):
            current_path = os.path.join(base_path, entry)
            if os.path.isdir(current_path):
                # 递归处理子目录
                sub_files = get_dir_files(current_path)
                file_list.extend(sub_files)
            elif os.path.isfile(current_path) and current_path.endswith('.py'):
                # 只处理Python文件（排除__init__.py）
                if os.path.basename(current_path) != '__init__.py':
                    file_list.append(current_path)
    return file_list


def path_to_module(path):
    """将文件路径转换为Python模块导入路径"""
    abs_path = os.path.abspath(path)
    base_dir = os.path.abspath('.')  # 项目根目录
    # 计算相对路径（相对于项目根目录）
    rel_path = os.path.relpath(abs_path, base_dir)
    # 转换为模块格式（替换路径分隔符为.，移除.py后缀）
    module_path = rel_path.replace(os.sep, '.').rsplit('.py', 1)[0]
    return module_path


def get_poc_module_list(mode):
    """根据模式加载对应的POC模块"""
    poc_module_list = []
    current_path = os.path.abspath('.')
    # 定义POC目录与模式的映射
    mode_dir_map = {
        'web': 'config/sword/web',
        'framework': 'config/sword/framework',
        'middleware': 'config/sword/middleware',
        'port': 'config/sword/ports'
    }
    # 获取当前模式对应的POC目录
    pocs_base_path = os.path.join(current_path, mode_dir_map[mode])

    # 检查目录是否存在
    if not os.path.exists(pocs_base_path):
        print(Fore.RED + f"[!] POC目录不存在: {pocs_base_path}")
        print(Fore.YELLOW + "[!] 请创建对应目录并放入POC文件（参考：config/sword/web/xxx.py）")
        return []

    # 获取目录下所有POC文件
    poc_path_list = get_dir_files(pocs_base_path)
    if not poc_path_list:
        print(Fore.YELLOW + f"[!] {pocs_base_path} 目录下未发现POC文件（.py）")
        return []

    print(Fore.YELLOW + f"[*] 发现 {len(poc_path_list)} 个POC文件，正在加载...")

    # 导入POC模块（验证是否包含verify方法）
    for poc_path in poc_path_list:
        try:
            module_path = path_to_module(poc_path)
            module = importlib.import_module(module_path)
            # 验证模块是否包含必要的verify方法
            if hasattr(module, 'verify') and callable(module.verify):
                poc_module_list.append(module)
                print(Fore.CYAN + f"[+] 加载成功: {module_path}")
        except Exception as e:
            print(Fore.RED + f"[!] 加载失败 {poc_path}: {str(e)}")
            continue

    return poc_module_list


def verify(target_list, poc_module_list):
    """执行POC验证逻辑"""
    results = []
    for target in target_list:
        for poc in poc_module_list:
            try:
                # 调用POC模块的verify方法（必须接收target和header参数）
                result = poc.verify(target)
                # 补充目标信息
                result['target'] = target
                results.append(result)
                # 实时输出进度
                status = "存在漏洞" if result['vulnerable'] else "检测中"
                print(Fore.YELLOW + f"[*] {status}: {result['name']} (目标: {target})")
            except Exception as e:
                print(Fore.RED + f"[!] POC执行出错 {poc.__name__}: {str(e)}")
                continue
    return results


def export_poc_result(output_path, url, mode, results):
    """导出POC扫描结果到CSV文件"""
    import csv

    # 确保输出路径以.csv结尾
    if not output_path.endswith('.csv'):
        output_path += '.csv'

    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # 写入表头
            writer.writerow(['目标URL', 'POC模式', 'POC名称', '是否存在漏洞', '漏洞详情', '扫描时间'])
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            for result in results:
                writer.writerow([
                    url,
                    mode,
                    result['name'],
                    '是' if result['vulnerable'] else '否',
                    result.get('details', '无'),
                    current_time
                ])

        print(Fore.GREEN + f"\n[+] POC扫描结果已导出至: {output_path}")
    except Exception as e:
        print(Fore.RED + f"[!] 导出结果失败: {str(e)}")