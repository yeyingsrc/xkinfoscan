import json
import hashlib
import requests
import re
import glob
import urllib3
from colorama import Fore, Style
import datetime  # 新增：用于时间处理

# 禁用SSL警告
urllib3.disable_warnings()


def cmsscan(args, scan_mode):  # 修复：接收主程序传递的scan_mode参数
    """CMS识别扫描主函数"""
    header = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
    }

    # 验证扫描模式有效性（主程序已处理，但二次验证确保安全）
    valid_modes = ['json', 'rapid', 'holdsword', 'fast']
    if scan_mode not in valid_modes:
        print(Fore.RED + f"[!] 无效的扫描模式: {scan_mode}")
        return

    # 处理目标URL（确保协议正确）
    url = args.url.strip()
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    print(Fore.CYAN + f"\n[+] 开始对目标 {url} 进行CMS识别（模块: {scan_mode}）")
    print("-" * 80)

    try:
        # 根据主程序传递的模式执行对应扫描
        if scan_mode == 'json':
            result = scan_json_mode(url, header)
        elif scan_mode == 'rapid':
            result = scan_rapid_mode(url, header)
        elif scan_mode == 'holdsword':
            result = scan_holdsword_mode(url, header)
        elif scan_mode == 'fast':
            result = scan_fast_mode(url, header)
        else:
            result = Fore.RED + "无效的扫描模式"

        # 输出结果
        print("\n" + Fore.GREEN + "=" * 80)
        print(f"[+] CMS识别完成")
        print(f"[+] 识别结果: {result}")
        print(Fore.GREEN + "=" * 80)

        # 导出CSV结果（如果指定了输出路径）
        if args.output:
            export_cms_result(args.output, url, scan_mode, result)

    except Exception as e:
        print(Fore.RED + f"\n[!] 扫描过程出错: {str(e)}")


def scan_json_mode(url, header):
    """JSON模式扫描（基于特征文件config/cms/data.json）"""
    try:
        # 尝试加载CMS特征库（JSON格式）
        with open('config/cms/data.json', 'r', encoding='utf-8', errors='ignore') as fp0:
            cms_data = json.load(fp0)

        for item in cms_data:
            try:
                # 拼接完整URL（目标URL + 特征路径）
                check_url = url + item.get("url", "")
                if not check_url.startswith(('http://', 'https://')):
                    continue  # 跳过无效URL
                print(Fore.CYAN + f"[*] 检查特征: {check_url}")

                # 发送请求并验证特征
                rsp = requests.get(check_url, headers=header, timeout=10, verify=False)
                rsphtml = rsp.text

                # 匹配关键词特征
                if item.get("re") and re.search(item["re"], rsphtml, re.IGNORECASE):
                    return f"{Fore.GREEN}目标使用的CMS为: {item['name']} | 来源: {check_url} | 关键词: {item['re']}"
                # 匹配MD5特征
                elif item.get("md5"):
                    md5 = hashlib.md5()
                    md5.update(rsphtml.encode())
                    if md5.hexdigest() == item["md5"]:
                        return f"{Fore.GREEN}目标使用的CMS为: {item['name']} | 来源: {check_url} | MD5: {item['md5']}"
            except (requests.exceptions.RequestException, Exception) as e:
                print(Fore.YELLOW + f"[!] 检查{check_url}时出错: {str(e)}（继续下一个）")
                continue

        return Fore.YELLOW + "未识别到已知CMS（JSON模式）"
    except FileNotFoundError:
        return Fore.RED + "未找到特征文件: config/cms/data.json（请确保该文件存在）"


def scan_rapid_mode(url, header):
    """快速模式扫描（基于特征文件config/cms/rapid.txt）"""
    try:
        # 加载快速扫描特征库（每行格式：路径 CMS名称）
        with open('config/cms/rapid.txt', 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]

        for line in wordlist:
            parts = line.strip().split(maxsplit=1)  # 允许CMS名称包含空格
            if len(parts) < 2:
                continue  # 跳过格式错误的行

            path, cms_name = parts[0], parts[1]
            try:
                check_url = url + path
                print(Fore.CYAN + f"[*] 检查路径: {check_url}")

                rsp = requests.get(check_url, headers=header, timeout=10, verify=False)
                # 若路径存在（状态码200），则匹配CMS
                if rsp.status_code == 200:
                    return f"{Fore.GREEN}目标使用的CMS为: {cms_name} | 来源: {check_url}"
            except (requests.exceptions.RequestException, Exception) as e:
                print(Fore.YELLOW + f"[!] 检查{check_url}时出错: {str(e)}（继续下一个）")
                continue

        return Fore.YELLOW + "未识别到已知CMS（快速模式）"
    except FileNotFoundError:
        return Fore.RED + "未找到特征文件: config/cms/rapid.txt（请确保该文件存在）"


def scan_holdsword_mode(url, header):
    """深度模式扫描（基于config/cms/yjcms目录下的特征文件）"""
    try:
        # 获取所有深度扫描特征文件
        cms_files = glob.glob('config/cms/yjconfig/cms/*')
        if not cms_files:
            return Fore.RED + "未找到深度扫描特征文件（请确保config/cms/yjcms目录下有特征文件）"

        for cmstype in cms_files:
            with open(cmstype, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue  # 跳过注释和空行
                    # 每行格式：路径------关键词------CMS名称
                    parts = line.split('------')
                    if len(parts) != 3:
                        continue  # 跳过格式错误的行

                    path, keyword, cms_name = parts[0], parts[1], parts[2]
                    try:
                        check_url = url + path
                        print(Fore.CYAN + f"[*] 深度检查: {check_url}（关键词: {keyword}）")

                        rsp = requests.get(check_url, headers=header, timeout=10, verify=False)
                        rsphtml = rsp.text

                        # 正则匹配关键词（不区分大小写）
                        if re.search(keyword, rsphtml, re.IGNORECASE):
                            return f"{Fore.GREEN}目标使用的CMS为: {cms_name} | 来源: {check_url} | 关键词: {keyword}"
                    except (requests.exceptions.RequestException, Exception) as e:
                        print(Fore.YELLOW + f"[!] 检查{check_url}时出错: {str(e)}（继续下一个）")
                        continue

        return Fore.YELLOW + "未识别到已知CMS（深度模式）"
    except Exception as e:
        return Fore.RED + f"深度扫描出错: {str(e)}"


def scan_fast_mode(url, header):
    """极速MD5模式扫描（基于特征文件config/cms/fast.txt）"""
    try:
        # 加载极速扫描特征库（每行格式：路径 CMS名称 MD5值）
        with open('config/cms/fast.txt', 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]

        result = None
        for line in wordlist:
            parts = line.strip().split(maxsplit=2)  # 允许CMS名称包含空格
            if len(parts) < 3:
                continue  # 跳过格式错误的行

            path, cms_name, target_md5 = parts[0], parts[1], parts[2]
            try:
                check_url = url + path
                print(Fore.CYAN + f"[*] 极速检查: {check_url}（MD5验证）")

                rsp = requests.get(check_url, headers=header, timeout=10, verify=False)
                rsphtml = rsp.text

                # 计算响应内容的MD5并匹配
                md5 = hashlib.md5()
                md5.update(rsphtml.encode())
                if md5.hexdigest() == target_md5:
                    result = f"{Fore.GREEN}目标使用的CMS为: {cms_name} | 来源: {check_url} | MD5: {target_md5}"
                    break  # 匹配成功后立即返回
            except (requests.exceptions.RequestException, Exception) as e:
                print(Fore.YELLOW + f"[!] 检查{check_url}时出错: {str(e)}（继续下一个）")
                continue

        return result if result else Fore.YELLOW + "未识别到已知CMS（极速模式）"
    except FileNotFoundError:
        return Fore.RED + "未找到特征文件: config/cms/fast.txt（请确保该文件存在）"


def export_cms_result(output_path, url, mode, result):
    """导出CMS识别结果到CSV文件"""
    import csv

    # 确保输出路径以.csv结尾
    if not output_path.endswith('.csv'):
        output_path += '.csv'

    try:
        # 获取当前时间（替代config.output.get_time，避免依赖）
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # 写入表头
            writer.writerow(['目标URL', '扫描模式', '识别结果', '扫描时间'])
            # 清除结果中的ANSI颜色代码
            clean_result = re.sub(r'\x1B\[[0-9;]*[mK]', '', result)
            writer.writerow([url, mode, clean_result, current_time])

        print(Fore.GREEN + f"\n[+] CMS识别结果已导出至: {output_path}（可直接用Excel打开）")
    except Exception as e:
        print(Fore.RED + f"[!] 导出结果失败: {str(e)}")