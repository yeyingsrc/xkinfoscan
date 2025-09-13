import argparse
import os
import re
import validators  # 用于URL/域名格式验证
from colorama import Fore, Style
from config import output
from config.dirscan import dirxkscan
from config.cmsscan import cmsscan
from config.domaininfo import domain_info_scan, get_domain_modules
from config.ipinfo import ip_info_scan
from config.pocscan import poc_scan
from config.infoleak import infoleak_scan  # 显式导入信息泄露模块
from config.ghosttrack import run_ghosttrack
from config.vuln.vuln_scanner import run_vuln_scan


def get_parser():
    """解析命令行参数，整合所有功能选项"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="xkInfoScan - 多功能网络信息扫描工具\n"
                    "支持目录扫描、CMS识别、POC检测、IP信息收集、域名信息查询、\n"
                    "信息泄露扫描、Web信息扫描及信息追踪（IP/手机号/用户名）"
    )
    query_group = parser.add_argument_group('查询参数')
    query_group.add_argument('-k', '--track', action='store_true', help='启用信息追踪模块（IP/手机号/用户名）')

    target_group = parser.add_argument_group('目标参数')
    target_group.add_argument('-u', '--url', type=str, required=False,
                              help='目标URL（需带http/https，如https://example.com）')
    target_group.add_argument('-d', '--domain', type=str, required=False,
                              help='目标域名（如example.com，不含协议头）')
    target_group.add_argument('-i', '--ip', type=str, required=False,
                              help='目标IP（支持单IP或网段，如192.168.1.1）')

    # 功能参数组（新增CDN模块支持）
    func_group = parser.add_argument_group('功能参数')
    # 在get_parser()的-s参数中添加leakattack
    func_group.add_argument('-s', '--scan', type=str, required=False,
                            choices=['dir', 'cms', 'poc', 'infoleak', 'vulnscan', 'webscan',
                                     'leakattack'],
                            help='扫描类型: dir(目录) | cms(CMS识别) | poc(漏洞检测) | infoleak(信息泄露) |\n'
                                 'vulnscan(常规漏洞扫描) | webscan(Web信息扫描) | leakattack(信息泄露攻击) |\n'
                                 '403bypass(403禁止访问绕过检测)')
    func_group.add_argument('--cms-mode', type=str, required=False,
                            choices=['json', 'rapid', 'holdsword', 'fast'],
                            help='CMS模式: json(详细) | rapid(快速) | holdsword(深度) | fast(极速)')
    func_group.add_argument('--poc-mode', type=str, required=False,
                            choices=['web', 'framework', 'middleware', 'port'],
                            help='POC模式: web(Web应用) | framework(框架) | middleware(中间件) | port(端口服务)')
    # 新增：在IP模式中添加cdn选项
    func_group.add_argument('--ip-mode', type=str, required=False,
                            choices=['base', 'domain', 'rdap', 'web_discovery', 'geo', 'port_scan', 'full', 'cdn'],
                            help='IP模式: base(基础) | domain(域名关联) | rdap(注册信息) | web_discovery(Web服务) | '
                                 'geo(地理信息) | port_scan(端口扫描) | full(全部) | cdn(CDN检测)')
    func_group.add_argument('--domain-mode', type=str, required=False,
                            choices=['whois', 'ip', 'dns', 'subdomain', 'all'],
                            help='域名模式: whois | ip | dns | subdomain | all(全部)')
    func_group.add_argument('--info-mode', type=str, required=False,
                            choices=['basic', 'deep', 'full'],
                            help='信息泄露扫描模式: basic(基础) | deep(深度) | full(全面)')
    # func_group.add_argument('-k', '--track', action='store_true',
    #                         help='启用信息追踪模块（支持IP/手机号/用户名/本机IP查询）')
    # func_group.add_argument('-c', '--company', action='store_true', help='启用企业信息查询模块（风鸟/爱企查）')


    # 通用参数组
    common_group = parser.add_argument_group('通用参数')
    common_group.add_argument('-o', '--output', type=str, required=False,
                              help='结果导出路径（支持CSV/JSON，如result.csv）')
    common_group.add_argument('-m', '--method', type=str, required=False,
                              choices=['head', 'get', 'post'], default='get',
                              help='HTTP请求方法（仅目录扫描，默认get）')
    common_group.add_argument('-t', '--threads', type=int, required=False, default=10,
                              help='线程数（目录/IP/信息泄露扫描，默认10，最大100）')
    common_group.add_argument('--debug', action='store_true',
                              help='开启调试模式（显示原始请求、响应及错误详情）')

    return parser.parse_args()


def is_valid_ip(ip):
    """验证IP地址格式合法性"""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    for group in match.groups():
        if int(group) < 0 or int(group) > 255:
            return False
    return True


def generate_ip_list(ip, scan_range):
    """根据网段类型生成IP列表（A段/B段/C段/单个IP）"""
    if not is_valid_ip(ip):
        raise ValueError("无效的IP地址格式（应为xxx.xxx.xxx.xxx）")

    # 提取IP四段
    ip_parts = list(map(int, ip.split('.')))  # [a, b, c, d]

    if scan_range == 'single':
        return [ip]

    elif scan_range == 'cidr':  # C段（前24位固定）
        a, b, c, _ = ip_parts
        return [f"{a}.{b}.{c}.{d}" for d in range(1, 256)]

    elif scan_range == 'b_segment':  # B段（前16位固定）
        a, b, _, _ = ip_parts
        ip_list = []
        for c in range(1, 256):
            for d in range(1, 256):
                ip_list.append(f"{a}.{b}.{c}.{d}")
        return ip_list

    elif scan_range == 'a_segment':  # A段（前8位固定）
        a, _, _, _ = ip_parts
        ip_list = []
        for b in range(1, 256):
            for c in range(1, 256):
                for d in range(1, 256):
                    ip_list.append(f"{a}.{b}.{c}.{d}")
        return ip_list

    else:
        raise ValueError("无效的扫描范围类型（应为single/cidr/b_segment/a_segment）")


def main():
    """主函数：协调所有扫描功能的执行流程"""
    output.logo()  # 显示工具Logo
    args = get_parser()

    # 参数互斥校验（确保唯一目标）
    target_count = sum(1 for x in [args.url, args.domain, args.ip,args.track] if x)
    if target_count > 1:
        print(Fore.RED + "[!] 错误：只能指定一个目标（-u/-d/-i/-k）")
        return

    if args.track:
        print(Fore.CYAN + "\n[+] 启用信息追踪模块（GhostTracker）")
        run_ghosttrack(args)
        return

    # 2. IP信息扫描逻辑
    if args.ip:
        # 验证IP格式
        if not is_valid_ip(args.ip):
            print(Fore.RED + f"[!] 无效IP地址：{args.ip}（应为xxx.xxx.xxx.xxx）")
            return

        # 选择扫描范围
        print(Fore.CYAN + "\n请选择扫描范围：")
        range_choices = {
            '1': ['single', '单个IP扫描（仅输入的IP）'],
            '2': ['cidr', 'C段扫描（如192.168.1.1-255，共255个IP）'],
            '3': ['b_segment', 'B段扫描（如192.168.0.1-255.255，共65535个IP）'],
            '4': ['a_segment', 'A段扫描（如10.0.0.1-255.255.255，共16777215个IP）']
        }
        for num, (range_type, desc) in range_choices.items():
            print(f"{num}. {Fore.GREEN}{range_type.ljust(12)} - {desc}")

        # 获取用户选择
        while True:
            range_choice = input("\n请输入范围选项（1-4）: ").strip()
            if range_choice in range_choices:
                scan_range = range_choices[range_choice][0]
                break
            else:
                print(Fore.RED + "无效选项，请输入1-4！")

        # 大网段警告
        if scan_range in ['b_segment', 'a_segment']:
            ip_count = 65535 if scan_range == 'b_segment' else 16777215
            print(Fore.YELLOW + f"\n[!] 警告：{range_choices[range_choice][1]}，可能需要数小时至数天")
            confirm = input(Fore.YELLOW + "是否继续？(y/N): ").strip().lower()
            if confirm != 'y':
                print(Fore.CYAN + "[+] 用户取消扫描")
                return

        # 生成IP列表
        try:
            ip_list = generate_ip_list(args.ip, scan_range)
            print(Fore.CYAN + f"\n[+] 已生成扫描IP列表（共{len(ip_list)}个IP）")
            # 线程数限制（最大100）
            args.threads = min(args.threads, 100)
            if len(ip_list) > 10000 and args.threads > 50:
                args.threads = 50
                print(Fore.YELLOW + f"[!] 大网段扫描自动限制线程数为50")
        except ValueError as e:
            print(Fore.RED + f"[!] {str(e)}")
            return

        # 选择IP扫描模块（新增CDN选项）
        ip_modules = {
            '1': ['base', '基础信息（类型/私有性/CDN检测）'],  # 更新描述
            '2': ['domain', '域名关联（绑定的网站）'],
            '3': ['rdap', '注册信息（ASN/运营商）'],
            '4': ['web_discovery', 'Web服务（HTTP/HTTPS）'],
            '5': ['geo', '地理信息（国家/城市）'],
            '6': ['port_scan', '端口扫描（常见服务识别）'],
            '7': ['full', '综合信息（整合所有模块）'],
            '8': ['cdn', 'CDN检测（IP段+ASN分析）']  # 新增CDN选项
        }
        scan_module = args.ip_mode
        if not scan_module:
            print(Fore.CYAN + "\n请选择IP信息扫描模块：")
            for num, (mode, desc) in ip_modules.items():
                print(f"{num}. {Fore.BLUE}{mode.ljust(12)} - {desc}")
            while True:
                sub_choice = input("请输入模块选项（1-8）: ").strip()  # 更新为1-8
                if sub_choice in ip_modules:
                    scan_module = ip_modules[sub_choice][0]
                    break
                else:
                    print(Fore.RED + "无效选项，请输入1-8！")  # 更新为1-8

        # 执行IP扫描
        ip_info_scan(args, scan_module, ip_list, debug=args.debug)
        return

    # 3. 域名信息扫描逻辑
    if args.domain:
        # 验证域名格式
        if not validators.domain(args.domain):
            print(Fore.RED + f"[!] 无效域名：{args.domain}（应为example.com格式）")
            return

        # 获取域名模块
        modules = get_domain_modules(args)
        domain_info_scan(args, modules)
        return

    # 4. URL相关扫描逻辑（目录/CMS/POC/信息泄露）
    if args.url:
        # 验证URL格式
        if not validators.url(args.url):
            print(Fore.RED + f"[!] 无效URL：{args.url}（需带http://或https://）")
            return

        # 选择扫描类型
        scan_type = args.scan
        if not scan_type:
            print(Fore.CYAN + "\n请选择扫描类型：")
            print(f"1. {Fore.GREEN}dir (目录扫描)")
            print(f"2. {Fore.YELLOW}cms (CMS识别)")
            print(f"3. {Fore.RED}poc (POC漏洞检测)")
            print(f"4. {Fore.MAGENTA}infoleak (信息泄露扫描)")
            print(f"5. {Fore.LIGHTWHITE_EX}vulnscan (常规漏洞扫描)")
            print(f"6. {Fore.LIGHTMAGENTA_EX}webscan (Web信息扫描，含JSFinder)")
            print(f"7. {Fore.BLUE}leakattack (信息泄露攻击，含SVN/Git/.DS_Store)")
            print(f"8. {Fore.YELLOW}403bypass (403禁止访问绕过检测)")
            while True:
                choice = input("请输入选项（1-8）: ").strip()
                if choice == '1':
                    scan_type = 'dir'
                    break
                elif choice == '2':
                    scan_type = 'cms'
                    break
                elif choice == '3':
                    scan_type = 'poc'
                    break
                elif choice == '4':
                    scan_type = 'infoleak'
                    break
                elif choice == '5':
                    scan_type = 'vulnscan'
                    break
                elif choice == '6':
                    scan_type = 'webscan'
                    break
                elif choice == '7':
                    scan_type = 'leakattack'
                    break
                elif choice == '8':
                    scan_type = '403bypass'
                    break
                else:
                    print(Fore.RED + "无效选项，请输入1-8！")
            if scan_type == 'webscan':
                print(Fore.CYAN + "\n请选择Web扫描工具：")
                print("1. jsfinder（提取JS中的URL和子域名）")
                print("2. apifinder（提取API接口和敏感信息）")
                while True:
                    tool_choice = input("请输入选项（1-2）: ").strip()
                    if tool_choice == '1':
                        from config.webscan.jsfinder import run_jsfinder
                        run_jsfinder(args)
                        break
                    elif tool_choice == '2':
                        from config.webscan.apifinder import run_apifinder
                        run_apifinder(args)
                        break
                    else:
                        print(Fore.RED + "无效选项，请输入1或2！")
                return
            if scan_type == '403bypass':
                # 导入403绕过模块的入口函数
                from config.webscan.bypass403 import run_403bypass
                print(Fore.CYAN + f"\n[+] 启用403绕过检测模块 | 目标: {args.url}")
                run_403bypass(args)  # 调用403绕过逻辑
                return
            if scan_type == 'leakattack':
                from config.leakattack import run_leakattack
                run_leakattack(args)
                return

            # 常规漏洞扫描模块（vulnscan）
            if scan_type == 'vulnscan':

                # 选择漏洞类型
                vuln_types = {
                    '1': ['unauthorized', '未授权访问漏洞'],
                    '2': ['weakpass', '弱密码检测'],
                    '3': ['all', '全部漏洞类型']
                }
                print(Fore.CYAN + "\n请选择漏洞类型：")
                for num, (vuln_code, vuln_name) in vuln_types.items():
                    print(f"{num}. {Fore.RED}{vuln_code.ljust(10)} - {vuln_name}")
                while True:
                    vuln_choice = input("请输入漏洞类型选项（1-3）: ").strip()
                    if vuln_choice in vuln_types:
                        selected_vuln = vuln_types[vuln_choice][0]
                        break
                    else:
                        print(Fore.RED + "无效选项，请输入1-3！")

                # 选择扫描模式（主动/被动）
                scan_modes = {
                    '1': ['active', '主动扫描（发送攻击载荷检测）'],
                    '2': ['passive', '被动扫描（分析正常请求响应）']
                }
                print(Fore.CYAN + "\n请选择扫描模式：")
                for num, (mode_code, mode_desc) in scan_modes.items():
                    print(f"{num}. {Fore.YELLOW}{mode_code.ljust(10)} - {mode_desc}")
                while True:
                    mode_choice = input("请输入模式选项（1-2）: ").strip()
                    if mode_choice in scan_modes:
                        selected_mode = scan_modes[mode_choice][0]
                        break
                    else:
                        print(Fore.RED + "无效选项，请输入1-2！")

                # 执行常规漏洞扫描
                print(
                    Fore.CYAN + f"\n[+] 开始常规漏洞扫描 | 目标: {args.url} | 漏洞类型: {selected_vuln} | 模式: {selected_mode}")
                run_vuln_scan(args, selected_vuln, selected_mode)
                return



        # 信息泄露扫描
        if scan_type == 'infoleak':
            # 信息泄露模式默认值
            if not args.info_mode:
                args.info_mode = 'full'  # 默认全面扫描
            print(Fore.CYAN + f"\n[+] 开始信息泄露扫描 | 模式: {args.info_mode} | 目标: {args.url}")
            infoleak_scan(args)
            return

        # 目录扫描
        if scan_type == 'dir':
            print(Fore.CYAN + f"\n[+] 开始目录扫描 | 方法: {args.method} | 线程: {args.threads} | 目标: {args.url}")
            dirxkscan(args)
            return

        # CMS识别
        if scan_type == 'cms':
            cms_modules = {
                '1': 'json', '2': 'rapid', '3': 'holdsword', '4': 'fast'
            }
            scan_mode = args.cms_mode
            if not scan_mode:
                print(Fore.CYAN + "\n请选择CMS扫描模块：")
                print(f"1. {Fore.MAGENTA}json - 详细输出（含版本信息）")
                print(f"2. {Fore.MAGENTA}rapid - 快速扫描（基础识别）")
                print(f"3. {Fore.MAGENTA}holdsword - 深度扫描（插件检测）")
                print(f"4. {Fore.MAGENTA}fast - 极速扫描（特征匹配）")
                while True:
                    sub_choice = input("请输入模块选项（1-4）: ").strip()
                    if sub_choice in cms_modules:
                        scan_mode = cms_modules[sub_choice]
                        break
                    else:
                        print(Fore.RED + "无效选项，请输入1-4！")
            print(Fore.CYAN + f"\n[+] 开始CMS识别 | 模式: {scan_mode} | 目标: {args.url}")
            cmsscan(args, scan_mode)
            return


        # POC漏洞检测
        if scan_type == 'poc':
            poc_modules = {
                '1': ['web', 'Web应用漏洞（SQL注入、XSS等）'],
                '2': ['framework', '框架漏洞（Struts2、Spring等）'],
                '3': ['middleware', '中间件漏洞（Tomcat、Nginx等）'],
                '4': ['port', '端口服务漏洞（Redis、MySQL等）']
            }
            poc_mode = args.poc_mode
            if not poc_mode:
                print(Fore.CYAN + "\n请选择POC检测子模块：")
                for num, (mode, desc) in poc_modules.items():
                    print(f"{num}. {Fore.RED}{mode.ljust(10)} - {desc}")
                while True:
                    sub_choice = input("请输入子模块选项（1-4）: ").strip()
                    if sub_choice in poc_modules:
                        poc_mode = poc_modules[sub_choice][0]
                        break
                    else:
                        print(Fore.RED + "无效选项，请输入1-4！")
            print(Fore.CYAN + f"\n[+] 开始POC检测 | 模式: {poc_mode} | 线程: {args.threads} | 目标: {args.url}")
            poc_scan(args, poc_mode)
            return



    # 未指定目标参数
    print(Fore.RED + "请指定目标参数以开始扫描：" + Style.RESET_ALL)
    print(Fore.YELLOW + "  信息追踪: -k（无需额外目标，支持IP/手机号/用户名查询）")
    print(Fore.YELLOW + "  IP扫描: -i IP地址 [--ip-mode 模块] (新增: --ip-mode cdn 进行CDN检测)")  # 更新帮助信息
    print(Fore.YELLOW + "  域名查询: -d 域名 [--domain-mode 模块]")
    print(Fore.YELLOW + "  URL扫描: -u URL -s [dir/cms/poc/infoleak]")
    print(Fore.YELLOW + "\n使用示例:")
    print(Fore.YELLOW + "  CDN检测: python xkinfoscan.py -i 1.1.1.1 --ip-mode cdn")  # 新增CDN示例
    print(Fore.YELLOW + "  信息追踪: python xkinfoscan.py -k")
    print(Fore.YELLOW + "  IP端口扫描: python xkinfoscan.py -i 192.168.1.1 --ip-mode port_scan -t 30")
    print(Fore.YELLOW + "  信息泄露扫描: python xkinfoscan.py -u https://example.com -s infoleak --info-mode deep")
    print(Fore.YELLOW + "  域名WHOIS查询: python xkinfoscan.py -d example.com --domain-mode whois")
    print(Fore.YELLOW + " 403 绕过检测: python xkinfoscan.py -u https://example.com -s 403bypass")


if __name__ == '__main__':
    try:
        # 确保线程数合理（1-100）
        args = get_parser()
        if args.threads < 1 or args.threads > 100:
            print(Fore.YELLOW + "[!] 线程数自动调整为1-100范围")
            args.threads = max(1, min(args.threads, 100))
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] 用户中断扫描进程" + Style.RESET_ALL)
    except Exception as e:
        if 'args' in locals() and args.debug:
            # 调试模式显示详细错误
            import traceback

            print(Fore.RED + f"\n[!] 程序异常终止: {traceback.format_exc()}")
        else:
            print(Fore.RED + f"\n[!] 程序异常终止: {str(e)}（使用--debug查看详情）")
