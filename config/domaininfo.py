import socket
import whois
import re
import requests
from lxml import etree
import dns.resolver
from colorama import Fore, Style
from config.output import get_time

# 通用请求头
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Connection': 'close'
}


# 颜色输出工具函数
def print_yellow(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)


def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)


# 模块1：WHOIS信息查询
def module_whois(domain):
    """WHOIS模块：查询域名注册信息"""
    result = {
        'module': 'whois',
        'status': 'success',
        'data': {},
        'message': ""
    }
    try:
        print_cyan(f"[*] WHOIS模块 - 查询域名: {domain}")
        w = whois.whois(domain)
        # 过滤空值
        filtered_data = {}
        for key, value in w.items():
            if value not in (None, '', [], {}) and str(value).strip() != '':
                filtered_data[key] = value
        if filtered_data:
            result['data'] = filtered_data
            result['message'] = "WHOIS信息查询成功"
        else:
            result['status'] = 'empty'
            result['message'] = "未查询到有效WHOIS信息（可能被隐私保护）"
        return result
    except whois.parser.PywhoisError:
        result['status'] = 'error'
        result['message'] = "域名可能不存在或无公开注册信息"
        return result
    except Exception as e:
        result['status'] = 'error'
        result['message'] = f"查询失败: {str(e)}"
        return result


# 模块2：IP解析查询
def module_ip(domain):
    """IP模块：解析域名对应的IP及关联信息"""
    result = {
        'module': 'ip',
        'status': 'success',
        'data': {},
        'message': ""
    }
    try:
        print_cyan(f"[*] IP模块 - 查询域名: {domain}")
        host_info = socket.gethostbyname_ex(domain)
        host_name, aliases, ip_list = host_info
        result['data'] = {
            'host_name': host_name,
            'aliases': aliases,
            'ip_list': ip_list
        }
        result['message'] = f"解析到 {len(ip_list)} 个IP地址"
        return result
    except socket.gaierror:
        result['status'] = 'error'
        result['message'] = "域名无法解析（可能不存在或DNS故障）"
        return result
    except Exception as e:
        result['status'] = 'error'
        result['message'] = f"解析出错: {str(e)}"
        return result


# 模块3：DNS记录查询
def module_dns(domain):
    """DNS模块：查询域名的全类型DNS记录"""
    result = {
        'module': 'dns',
        'status': 'success',
        'data': {},
        'message': ""
    }
    record_types = ['A', 'MX', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'SRV', 'AAAA']
    records = {}

    try:
        print_cyan(f"[*] DNS模块 - 查询域名: {domain}")
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                if rtype == 'MX':
                    records[rtype] = [f"优先级：{ans.preference}，值：{ans.exchange}" for ans in answers]
                elif rtype == 'SOA':
                    soa = answers[0]
                    records[rtype] = [
                        f"主域名服务器：{soa.mname}",
                        f"管理员邮箱：{soa.rname}",
                        f"序列号：{soa.serial}",
                        f"刷新时间：{soa.refresh}",
                        f"重试时间：{soa.retry}",
                        f"过期时间：{soa.expire}",
                        f"最小TTL：{soa.minimum}"
                    ]
                elif rtype == 'SRV':
                    records[rtype] = [
                        f"优先级：{ans.priority}，权重：{ans.weight}，端口：{ans.port}，目标：{ans.target}"
                        for ans in answers
                    ]
                else:
                    records[rtype] = [str(ans) for ans in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = "无此类型记录"
            except dns.resolver.Timeout:
                records[rtype] = "查询超时"
            except Exception as e:
                records[rtype] = f"查询失败: {str(e)}"

        result['data'] = records
        result['message'] = "DNS记录查询完成"
        return result
    except Exception as e:
        result['status'] = 'error'
        result['message'] = f"DNS模块出错: {str(e)}"
        return result


# 模块4：子域名枚举
def module_subdomain(domain):
    """子域名模块：枚举域名的子域名及IP"""
    result = {
        'module': 'subdomain',
        'status': 'success',
        'data': [],
        'message': ""
    }
    try:
        print_cyan(f"[*] 子域名模块 - 查询域名: {domain}")
        # 从多个来源获取子域名
        crt_subs = get_subdomains_crtsh(domain)
        ip138_subs = get_subdomains_ip138(domain)

        # 合并去重
        all_subs = []
        seen = set()
        for sub in crt_subs + ip138_subs:
            if sub not in seen:
                seen.add(sub)
                all_subs.append(sub)

        # 解析每个子域名的IP
        subdomains_with_ip = []
        for sub in all_subs:
            ip = resolve_subdomain_ip(sub)
            subdomains_with_ip.append({
                'subdomain': sub,
                'ip': ip
            })

        result['data'] = subdomains_with_ip
        result['message'] = f"共发现 {len(subdomains_with_ip)} 个子域名"
        return result
    except Exception as e:
        result['status'] = 'error'
        result['message'] = f"子域名枚举出错: {str(e)}"
        return result


# 子域名查询辅助函数（来源：crt.sh）
def get_subdomains_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=*.{domain}"
        response = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
        response.raise_for_status()

        html = etree.HTML(response.text)
        raw_domains = html.xpath("//table//tr/td[6]/text()")
        clean_domains = []
        for d in raw_domains:
            d_clean = d.strip().lstrip('*.')
            if d_clean and domain in d_clean and d_clean not in clean_domains:
                if '<BR>' in d_clean:
                    for sub in d_clean.split('<BR>'):
                        sub = sub.strip().lstrip('*.')
                        if sub not in clean_domains:
                            clean_domains.append(sub)
                else:
                    clean_domains.append(d_clean)
        return clean_domains
    except Exception:
        return []


# 子域名查询辅助函数（来源：ip138.com）
def get_subdomains_ip138(domain):
    try:
        url = f"http://site.ip138.com/{domain}/domain.htm"
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()

        pattern = re.compile(r'target="_blank">(.*?)</a></p>')
        raw_subdomains = pattern.findall(response.text)
        clean_subdomains = []
        for sub in raw_subdomains:
            sub_clean = sub.strip()
            if sub_clean and sub_clean.endswith(domain) and sub_clean != domain and sub_clean not in clean_subdomains:
                clean_subdomains.append(sub_clean)
        return clean_subdomains
    except Exception:
        return []


# 子域名IP解析辅助函数
def resolve_subdomain_ip(subdomain):
    try:
        ip_list = socket.gethostbyname_ex(subdomain)[2]
        return ', '.join(ip_list)
    except (socket.gaierror, IndexError):
        return "解析失败"
    except Exception as e:
        return f"错误: {str(e)}"


# 汇总报告生成
def generate_summary(modules, results):
    """生成域名查询汇总报告"""
    summary = []
    summary.append(f"\n{'=' * 70}")
    summary.append(f"[域名信息汇总报告] {get_time()}")
    summary.append(f"{'-' * 70}")

    # 统计各模块状态
    success_count = sum(1 for res in results if res['status'] == 'success')
    empty_count = sum(1 for res in results if res['status'] == 'empty')
    error_count = sum(1 for res in results if res['status'] == 'error')

    summary.append(f"1. 总模块数：{len(modules)} 个")
    summary.append(f"2. 成功查询：{success_count} 个")
    summary.append(f"3. 无有效数据：{empty_count} 个")
    summary.append(f"4. 查询失败：{error_count} 个")
    summary.append(f"{'-' * 70}")

    # 模块详情
    for i, res in enumerate(results, 1):
        status = {
            'success': '成功',
            'empty': '无数据',
            'error': '失败'
        }[res['status']]
        summary.append(f"  {i}. 模块: {res['module']} | 状态: {status} | {res['message']}")

    summary.append(f"{'=' * 70}")
    return "\n".join(summary)


# 模块输出格式化
def print_module_result(result):
    """格式化输出单个模块的结果"""
    print_cyan("\n" + "=" * 60)
    print_cyan(f"[{result['module'].upper()}模块结果] {result['message']}")
    print_cyan("-" * 60)

    if result['status'] == 'success' and result['data']:
        if result['module'] == 'whois':
            # WHOIS结果格式化
            for key, value in result['data'].items():
                if isinstance(value, list):
                    value_str = "\n      ".join(map(str, value))
                    print_yellow(f"{key}：\n      {value_str}")
                else:
                    print_yellow(f"{key}：{value}")

        elif result['module'] == 'ip':
            # IP结果格式化
            data = result['data']
            print_yellow(f"主机名：{data['host_name']}")
            print_yellow(f"别名列表：{', '.join(data['aliases']) if data['aliases'] else '无'}")
            print_yellow(f"IP地址列表：{', '.join(data['ip_list'])}")

        elif result['module'] == 'dns':
            # DNS结果格式化
            for rtype, values in result['data'].items():
                print_yellow(f"【{rtype}记录】")
                if isinstance(values, list):
                    for v in values:
                        print_yellow(f"  - {v}")
                else:
                    print_yellow(f"  - {values}")

        elif result['module'] == 'subdomain':
            # 子域名结果格式化
            for i, item in enumerate(result['data'], 1):
                print_yellow(f"  {i}. {item['subdomain']} | IP: {item['ip']}")
    else:
        # 输出状态信息
        print_yellow(result['message'])


# 主函数：域名信息扫描入口
def domain_info_scan(args, modules=None):
    """域名信息扫描主函数（支持模块选择）"""
    domain = args.domain
    print_cyan(f"\n[+] 开始域名信息扫描：{domain} {get_time()}")

    # 定义可用模块
    all_modules = {
        '1': {'name': 'whois', 'desc': 'WHOIS注册信息（域名所有者、过期时间等）'},
        '2': {'name': 'ip', 'desc': 'IP解析（域名对应的IP地址及别名）'},
        '3': {'name': 'dns', 'desc': 'DNS记录（A/MX/NS等全类型记录）'},
        '4': {'name': 'subdomain', 'desc': '子域名枚举（含IP解析）'},
        '5': {'name': 'all', 'desc': '所有模块（依次执行以上全部查询）'}
    }

    # 选择模块（优先命令行参数，无则交互式选择）
    if not modules:
        print_cyan("\n请选择域名信息查询模块：")
        for num, info in all_modules.items():
            print(f"{num}. {Fore.GREEN}{info['name'].ljust(10)} - {info['desc']}")

        while True:
            choice = input("\n请输入模块选项（1-5）: ").strip()
            if choice in all_modules:
                selected = all_modules[choice]['name']
                break
            else:
                print(Fore.RED + "无效选项，请输入1-5！")

        # 处理"所有模块"选项
        if selected == 'all':
            modules = [m['name'] for m in all_modules.values() if m['name'] != 'all']
        else:
            modules = [selected]

    # 执行选中的模块
    results = []
    for module in modules:
        if module == 'whois':
            res = module_whois(domain)
        elif module == 'ip':
            res = module_ip(domain)
        elif module == 'dns':
            res = module_dns(domain)
        elif module == 'subdomain':
            res = module_subdomain(domain)
        else:
            continue
        results.append(res)
        print_module_result(res)  # 实时输出模块结果

    # 输出汇总报告
    print_green(generate_summary(modules, results))


# 命令行参数支持（供主程序调用）
def get_domain_modules(args):
    """从命令行参数获取模块（如需扩展）"""
    if hasattr(args, 'domain_mode') and args.domain_mode in ['whois', 'ip', 'dns', 'subdomain', 'all']:
        if args.domain_mode == 'all':
            return ['whois', 'ip', 'dns', 'subdomain']
        else:
            return [args.domain_mode]
    return None