import json
import requests
import time
import os
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from colorama import Fore, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 忽略SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 颜色输出函数（与项目统一）
def print_green(text):
    return Fore.GREEN + str(text) + Style.RESET_ALL  # 确保所有输入都转为字符串


def print_red(text):
    return Fore.RED + str(text) + Style.RESET_ALL


def print_cyan(text):
    return Fore.CYAN + str(text) + Style.RESET_ALL


def print_yellow(text):
    return Fore.YELLOW + str(text) + Style.RESET_ALL


def print_white(text):
    return Fore.WHITE + str(text) + Style.RESET_ALL


class GhostTracker:
    def __init__(self):
        # 初始化社交平台列表（用于用户名追踪）
        self.social_platforms = [
            {"url": "https://www.facebook.com/{}", "name": "Facebook"},
            {"url": "https://www.twitter.com/{}", "name": "Twitter"},
            {"url": "https://www.instagram.com/{}", "name": "Instagram"},
            {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
            {"url": "https://www.github.com/{}", "name": "GitHub"},
            {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
            {"url": "https://www.tumblr.com/{}", "name": "Tumblr"},
            {"url": "https://www.youtube.com/{}", "name": "Youtube"},
            {"url": "https://soundcloud.com/{}", "name": "SoundCloud"},
            {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
            {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
            {"url": "https://www.behance.net/{}", "name": "Behance"},
            {"url": "https://www.medium.com/@{}", "name": "Medium"},
            {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
            {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
            {"url": "https://www.periscope.tv/{}", "name": "Periscope"},
            {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
            {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
            {"url": "https://www.stumbleupon.com/stumbler/{}", "name": "StumbleUpon"},
            {"url": "https://www.ello.co/{}", "name": "Ello"},
            {"url": "https://www.producthunt.com/@{}", "name": "Product Hunt"},
            {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
            {"url": "https://www.telegram.me/{}", "name": "Telegram"},
            {"url": "https://www.weheartit.com/{}", "name": "We Heart It"}
        ]

    # 1. IP追踪模块
    def track_ip(self, ip):
        print(print_cyan(f"\n[+] 开始IP追踪 | 目标IP: {ip}"))
        print(print_cyan("=" * 60))
        try:
            # 调用IP信息API
            response = requests.get(f"http://ipwho.is/{ip}", timeout=10)
            response.raise_for_status()
            ip_data = response.json()

            # 解析并显示IP信息
            print(f"IP目标        : {print_green(ip)}")
            print(f"IP类型        : {print_green(ip_data.get('type', '未知'))}")
            print(f"国家          : {print_green(ip_data.get('country', '未知'))}")
            print(f"国家代码      : {print_green(ip_data.get('country_code', '未知'))}")
            print(f"城市          : {print_green(ip_data.get('city', '未知'))}")
            print(f"大洲          : {print_green(ip_data.get('continent', '未知'))}")
            print(f"大洲代码      : {print_green(ip_data.get('continent_code', '未知'))}")
            print(f"地区          : {print_green(ip_data.get('region', '未知'))}")
            print(f"地区代码      : {print_green(ip_data.get('region_code', '未知'))}")

            # 经纬度与地图链接（修复浮点数转换问题）
            lat = ip_data.get('latitude')
            lon = ip_data.get('longitude')
            if lat and lon:
                # 将浮点数转换为字符串
                lat_str = str(lat)
                lon_str = str(lon)
                print(f"纬度          : {print_green(lat_str)}")
                print(f"经度          : {print_green(lon_str)}")
                print(f"地图链接      : {print_green(f'https://www.google.com/maps/@{lat_str},{lon_str},8z')}")
            else:
                print(f"纬度          : {print_yellow('未知')}")
                print(f"经度          : {print_yellow('未知')}")
                print(f"地图链接      : {print_yellow('无法生成')}")

            # 其他信息
            print(f"是否欧盟      : {print_green(ip_data.get('is_eu', '未知'))}")
            print(f"邮编          : {print_green(ip_data.get('postal', '未知'))}")
            print(f"国家区号      : {print_green(ip_data.get('calling_code', '未知'))}")
            print(f"首都          : {print_green(ip_data.get('capital', '未知'))}")
            print(f"邻国          : {print_green(ip_data.get('borders', '未知'))}")
            print(f"国家旗帜      : {print_green(ip_data.get('flag', {}).get('emoji', '未知'))}")

            # 网络信息
            connection = ip_data.get('connection', {})
            print(f"ASN           : {print_green(connection.get('asn', '未知'))}")
            print(f"组织          : {print_green(connection.get('org', '未知'))}")
            print(f"ISP           : {print_green(connection.get('isp', '未知'))}")
            print(f"域名          : {print_green(connection.get('domain', '未知'))}")

            # 时区信息
            tz = ip_data.get('timezone', {})
            print(f"时区ID        : {print_green(tz.get('id', '未知'))}")
            print(f"时区缩写      : {print_green(tz.get('abbr', '未知'))}")
            print(f"是否夏令时    : {print_green(tz.get('is_dst', '未知'))}")
            print(f"时区偏移      : {print_green(tz.get('offset', '未知'))}")
            print(f"UTC时间       : {print_green(tz.get('utc', '未知'))}")
            print(f"当前时间      : {print_green(tz.get('current_time', '未知'))}")

        except Exception as e:
            print(print_red(f"[!] IP追踪失败: {str(e)}"))
        print(print_cyan("=" * 60))

    # 2. 手机号追踪模块 - 修复整数拼接错误
    def track_phone(self, phone_number):
        print(print_cyan(f"\n[+] 开始手机号追踪 | 目标号码: {phone_number}"))
        print(print_cyan("=" * 60))
        default_region = "CN"  # 针对中国号码优化默认地区
        try:
            # 解析手机号
            parsed_num = phonenumbers.parse(phone_number, default_region)

            # 提取手机号信息
            region_code = phonenumbers.region_code_for_number(parsed_num)
            operator = carrier.name_for_number(parsed_num, "zh-CN") or "未知"  # 使用中文运营商名称
            location = geocoder.description_for_number(parsed_num, "zh-CN") or "未知"  # 使用中文地区名
            is_valid = phonenumbers.is_valid_number(parsed_num)
            is_possible = phonenumbers.is_possible_number(parsed_num)
            intl_format = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            mobile_format = phonenumbers.format_number_for_mobile_dialing(parsed_num, default_region,
                                                                          with_formatting=True)
            num_type = phonenumbers.number_type(parsed_num)
            timezones = timezone.time_zones_for_number(parsed_num)

            # 显示结果 - 所有数字类型都转换为字符串
            print(f"地区          : {print_green(location)}")
            print(f"地区代码      : {print_green(region_code)}")
            print(f"时区          : {print_green(', '.join(timezones) if timezones else '未知')}")
            print(f"运营商        : {print_green(operator)}")
            print(f"号码有效性    : {print_green(is_valid)}")
            print(f"号码可能性    : {print_green(is_possible)}")
            print(f"国际格式      : {print_green(intl_format)}")
            print(f"手机拨号格式  : {print_green(mobile_format)}")
            print(f"原始号码      : {print_green(str(parsed_num.national_number))}")  # 整数转字符串
            print(
                f"E.164格式     : {print_green(phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164))}")
            print(f"国家代码      : {print_green(str(parsed_num.country_code))}")  # 整数转字符串
            print(f"本地号码      : {print_green(str(parsed_num.national_number))}")  # 整数转字符串

            # 号码类型判断
            if num_type == phonenumbers.PhoneNumberType.MOBILE:
                print(f"号码类型      : {print_green('手机号码')}")
            elif num_type == phonenumbers.PhoneNumberType.FIXED_LINE:
                print(f"号码类型      : {print_green('固定电话')}")
            else:
                print(f"号码类型      : {print_green('其他类型')}")

        except phonenumbers.phonenumberutil.NumberParseException as e:
            print(print_red(f"[!] 手机号解析失败: {str(e)}（请输入正确格式，如+8618811112222）"))
        except Exception as e:
            print(print_red(f"[!] 手机号追踪失败: {str(e)}"))
        print(print_cyan("=" * 60))

    # 3. 用户名追踪模块（社交平台检测）
    def track_username(self, username):
        print(print_cyan(f"\n[+] 开始用户名追踪 | 目标用户名: {username}"))
        print(print_cyan("=" * 60))
        results = []
        try:
            print(print_yellow(
                f"[*] 正在检测{len(self.social_platforms)}个社交平台，耗时约{len(self.social_platforms) * 0.5}秒..."))
            for platform in self.social_platforms:
                time.sleep(0.5)  # 延迟避免请求过于频繁
                url = platform["url"].format(username)
                try:
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    # 判断用户名是否存在（状态码200且无跳转至404页面）
                    if response.status_code == 200 and "404" not in response.url and "not found" not in response.text.lower():
                        results.append({"platform": platform["name"], "status": "存在", "url": url})
                    else:
                        results.append({"platform": platform["name"], "status": "不存在", "url": url})
                except Exception:
                    results.append({"platform": platform["name"], "status": "无法访问", "url": url})

            # 显示结果
            found_count = sum(1 for res in results if res["status"] == "存在")
            print(print_green(f"[+] 检测完成，共发现{found_count}个平台存在该用户名："))
            for res in results:
                if res["status"] == "存在":
                    print(f"[+] {res['platform']} : {print_green(res['url'])}")
                elif res["status"] == "不存在":
                    print(f"[-] {res['platform']} : {print_yellow(res['status'])}")
                else:
                    print(f"[!] {res['platform']} : {print_red(res['status'])}")

        except Exception as e:
            print(print_red(f"[!] 用户名追踪失败: {str(e)}"))
        print(print_cyan("=" * 60))

    # 4. 显示本机IP模块
    def show_local_ip(self):
        print(print_cyan("\n[+] 显示本机IP信息"))
        print(print_cyan("=" * 60))
        try:
            # 获取本机公网IP
            ip_response = requests.get("https://api.ipify.org", timeout=5)
            local_ip = ip_response.text.strip()
            print(f"本机公网IP    : {print_green(local_ip)}")

            # 补充本机IP的详细信息
            self.track_ip(local_ip)  # 复用IP追踪功能

        except Exception as e:
            print(print_red(f"[!] 获取本机IP失败: {str(e)}"))
        print(print_cyan("=" * 60))

    # 选择追踪模块
    def select_module(self):
        print(print_cyan("\n" + "=" * 80))
        print(print_cyan("          GhostTracker 信息追踪模块          "))
        print(print_cyan("=" * 80))
        print(print_cyan("\n可用追踪模块："))
        modules = [
            {"num": 1, "name": "IP追踪", "desc": "获取目标IP的地理位置、ISP等信息"},
            {"num": 2, "name": "本机IP查询", "desc": "显示本机公网IP及详细信息"},
            {"num": 3, "name": "手机号追踪", "desc": "获取手机号的运营商、地区等信息"},
            {"num": 4, "name": "用户名追踪", "desc": "检测用户名在各社交平台的存在情况"}
        ]
        for mod in modules:
            print(f"{mod['num']}. {mod['name']} - {mod['desc']}")
        print("0. 退出模块")

        # 选择模块
        while True:
            choice = input("\n请输入模块编号: ").strip()
            if not choice.isdigit():
                print(print_red("无效输入，请输入数字！"))
                continue
            choice = int(choice)
            if choice == 0:
                print(print_cyan("\n[+] 退出GhostTracker模块"))
                return
            elif choice in [mod["num"] for mod in modules]:
                self.run_module(choice)
                break
            else:
                print(print_red("编号超出范围，请重新输入！"))

    # 运行选中的模块
    def run_module(self, module_num):
        if module_num == 1:
            # IP追踪
            ip = input("\n请输入目标IP地址: ").strip()
            self.track_ip(ip)
        elif module_num == 2:
            # 本机IP查询
            self.show_local_ip()
        elif module_num == 3:
            # 手机号追踪
            phone = input("\n请输入目标手机号（格式：+国家代码号码，如+8618811112222）: ").strip()
            self.track_phone(phone)
        elif module_num == 4:
            # 用户名追踪
            username = input("\n请输入目标用户名: ").strip()
            self.track_username(username)

        # 模块运行后返回选择菜单
        while True:
            continue_choice = input("\n是否继续使用其他模块？(y/N): ").strip().lower()
            if continue_choice in ['y', 'yes']:
                self.select_module()
                break
            elif continue_choice in ['n', 'no', '']:
                print(print_cyan("\n[+] 退出GhostTracker模块"))
                break
            else:
                print(print_red("无效输入，请输入y或n！"))


# 模块入口函数（供主程序调用）
def run_ghosttrack(args):
    """GhostTracker模块入口（-k参数触发）"""
    tracker = GhostTracker()
    tracker.select_module()
