#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
li_domain_scanner.py

一个灵活的 .li 域名可用性扫描工具。
允许用户根据长度、字符集、生成方法（所有组合、字典、重复模式、拼音）
等条件组合来扫描域名。
"""

import socket
import time
import string
import itertools
import argparse
import sys
import re
from typing import Generator, Dict, Any, Optional, Set, List, Iterable

# --- 常量定义 ---
LI_WHOIS_HOST = "whois.nic.ch"  # .li 域名的 WHOIS 服务器地址
LI_WHOIS_PORT = 4343            # .li 域名的 WHOIS 服务器端口
SOCKET_TIMEOUT = 10             # Socket 连接和读取超时时间 (秒)
DEFAULT_DELAY = 1.0             # 默认两次查询之间的延迟时间 (秒)
MAX_RETRIES = 2                 # 连接失败时的最大重试次数

# 基础字符集
LETTERS = string.ascii_lowercase
DIGITS = string.digits
ALNUM = LETTERS + DIGITS

# 预编译正则表达式
REPEAT_PATTERN_CACHE = {}  # 重复模式正则表达式缓存

# --- 核心 WHOIS 查询函数 ---

def check_li_domain(domain_base: str, retry_count: int = 0) -> Dict[str, Any]:
    """
    检查单个 .li 域名是否可用。

    通过连接到官方 WHOIS 服务器的特定端口来查询。
    解析服务器返回的状态码，并提供详细的错误处理。

    Args:
        domain_base: 不包含 '.li' 的域名主体部分 (例如: 'example')。
        retry_count: 内部重试计数器。

    Returns:
        一个包含查询结果的字典:
        {
            'domain': 查询的完整域名 (例如: 'example.li'),
            'status': 英文状态 ('available', 'unavailable', etc.),
            'status_cn': 中文状态描述,
            'raw_code': 原始整数状态码 (-99 到 1) 或 None,
            'raw_response': 服务器原始响应或错误信息。
        }
    """
    domain_full = f"{domain_base}.li"
    result = {
        'domain': domain_full,
        'status': 'unknown_error',
        'status_cn': '未知错误',
        'raw_code': None,
        'raw_response': ''
    }

    sock = None
    try:
        # 建立 TCP 连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)  # 设置连接超时
        sock.connect((LI_WHOIS_HOST, LI_WHOIS_PORT))

        # 发送查询 (UTF-8 编码, 以 \r\n 结尾)
        query = f"{domain_full}\r\n".encode('utf-8')
        sock.sendall(query)

        # 接收响应
        response_bytes = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_bytes.extend(chunk)

                # 如果响应包含完整内容可以提前退出
                if b'\n\n' in response_bytes or len(response_bytes) > 8192:
                    break
            except socket.timeout:
                # 接收超时但已有数据，可能已完成
                if response_bytes:
                    break
                raise

        # 解码响应 (UTF-8, 忽略错误) 并清理
        response_text = response_bytes.decode('utf-8', errors='ignore').strip()
        result['raw_response'] = response_text

        # --- 解析响应 ---
        if not response_text:
            result['status'] = 'network_error'
            result['status_cn'] = '网络错误 (空响应)'
            result['raw_response'] = "从服务器收到空的响应。"
            return result

        # 提取第一行并查找状态码
        first_line = response_text.split('\n', 1)[0].strip()
        if ':' not in first_line:
            result['status'] = 'unknown_error'
            result['status_cn'] = '未知错误 (无法解析代码)'
            result['raw_response'] += "\n错误: 无法解析响应代码 (未找到冒号)."
            return result

        code_str = first_line.split(':', 1)[0].strip()
        try:
            code = int(code_str)
            result['raw_code'] = code

            # 映射状态码到状态
            if code == 1:
                result['status'] = 'available'
                result['status_cn'] = '可以注册'
            elif code == 0:
                result['status'] = 'unavailable'
                result['status_cn'] = '已被注册'
            elif code == -1:
                result['status'] = 'invalid_query'
                result['status_cn'] = '无效查询'
            elif code == -95:
                result['status'] = 'rate_limited'
                result['status_cn'] = '访问受限 (稍后重试)'
            elif code == -99:
                result['status'] = 'server_error'
                result['status_cn'] = '服务器临时错误 (稍后重试)'
            else:
                result['status'] = 'unknown_error'
                result['status_cn'] = f'未知错误 (代码: {code})'

        except ValueError:
            result['status'] = 'unknown_error'
            result['status_cn'] = '未知错误 (代码解析失败)'
            result['raw_response'] += f"\n错误: 无法将响应代码 '{code_str}' 解析为整数。"

    # --- 异常处理 ---
    except socket.timeout:
        result['status'] = 'network_error'
        result['status_cn'] = '网络错误 (超时)'
        result['raw_response'] = f"连接或读取超时 ({SOCKET_TIMEOUT} 秒)."

        # 尝试重试
        if retry_count < MAX_RETRIES:
            time.sleep(1)  # 重试前等待一秒
            return check_li_domain(domain_base, retry_count + 1)

    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        result['status'] = 'network_error'
        result['status_cn'] = '网络错误 (连接失败)'
        result['raw_response'] = f"连接到 {LI_WHOIS_HOST}:{LI_WHOIS_PORT} 时发生网络错误 - {e}"

        # 尝试重试
        if retry_count < MAX_RETRIES:
            time.sleep(1)  # 重试前等待一秒
            return check_li_domain(domain_base, retry_count + 1)

    except Exception as e:
        # 捕获任何其他意外错误
        result['status'] = 'unknown_error'
        result['status_cn'] = '未知错误 (程序异常)'
        result['raw_response'] = f"发生意外错误: {e}"
    finally:
        # 确保 socket 被关闭
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            finally:
                sock.close()

    return result

# --- 域名规则和字符集处理 ---

def get_charset(chars_arg: str) -> str:
    """根据命令行参数 (--chars) 返回实际的字符集字符串。"""
    if chars_arg == 'letters': return LETTERS
    elif chars_arg == 'digits': return DIGITS
    elif chars_arg == 'alnum': return ALNUM
    elif chars_arg == 'letters-hyphen': return LETTERS + '-'
    elif chars_arg == 'digits-hyphen': return DIGITS + '-'
    elif chars_arg == 'alnum-hyphen': return ALNUM + '-'
    else:
        # argparse 的 choices 应该阻止这种情况，但作为后备
        raise ValueError(f"内部错误：未知的字符集参数: {chars_arg}")

def is_valid_domain_base(domain_base: str, allow_hyphen: bool) -> bool:
    """
    检查域名主体部分是否符合基本规则。
    - 非空
    - 不包含点 '.'
    - 如果允许连字符：不能在开头或结尾
    """
    if not domain_base: return False
    if '.' in domain_base: return False
    if allow_hyphen and '-' in domain_base:
        if domain_base.startswith('-') or domain_base.endswith('-'):
            return False
    elif not allow_hyphen and '-' in domain_base:
        return False
    return True

def contains_only_allowed_chars(text: str, allowed_chars: str) -> bool:
    """检查字符串是否只包含允许的字符集中的字符。"""
    # 使用集合提高查找效率
    allowed_set = set(allowed_chars)
    return all(char in allowed_set for char in text)

def get_repeat_pattern(min_repeat_count: int):
    """获取预编译的重复模式正则表达式"""
    if min_repeat_count not in REPEAT_PATTERN_CACHE:
        pattern_str = r"([a-zA-Z0-9])\1{" + str(min_repeat_count - 1) + r",}"
        REPEAT_PATTERN_CACHE[min_repeat_count] = re.compile(pattern_str)
    return REPEAT_PATTERN_CACHE[min_repeat_count]

def has_min_repeats(text: str, min_repeat_count: int) -> bool:
    """
    检查字符串是否包含至少 N 个连续相同的字母或数字。
    使用缓存的正则表达式提高效率。
    """
    if min_repeat_count < 2: return True  # 小于2个不算重复
    pattern = get_repeat_pattern(min_repeat_count)
    return bool(pattern.search(text))

# --- 域名生成器 ---

def generate_all_combinations(length: int, charset: str) -> Generator[str, None, None]:
    """生成器：生成指定长度和字符集的所有组合。"""
    if length <= 0: return
    for item in itertools.product(charset, repeat=length):
        yield "".join(item)

def generate_from_file(filepath: str, length: int, allowed_charset: str) -> Generator[str, None, None]:
    """
    生成器：从文件读取单词/拼音，按长度和允许的字符集过滤。
    内部使用 set 去除文件中可能存在的重复行。
    """
    try:
        seen_in_file = set()  # 用于文件内去重
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip().lower()
                # 检查长度、是否已见过、是否只包含允许字符
                if (len(word) == length and
                    word not in seen_in_file and
                    contains_only_allowed_chars(word, allowed_charset)):
                    yield word
                    seen_in_file.add(word)
    except FileNotFoundError:
        print(f"警告: 文件未找到 '{filepath}'，将跳过此生成方法。", file=sys.stderr)
    except Exception as e:
        print(f"警告: 读取文件 '{filepath}' 时出错: {e}，将跳过此生成方法。", file=sys.stderr)

def generate_repeating_patterns(length: int, charset: str, min_repeats: int) -> Generator[str, None, None]:
    """
    生成器：生成所有组合，并筛选出包含指定最少重复字符的。
    """
    if length <= 0 or min_repeats < 2: return

    # 预编译正则表达式
    pattern = get_repeat_pattern(min_repeats)

    # 遍历所有可能组合
    for item in itertools.product(charset, repeat=length):
        candidate = "".join(item)
        # 检查是否包含足够的重复
        if pattern.search(candidate):
            yield candidate

# --- 主域名生成协调函数 ---

def generate_domains(
    length: int,
    chars_arg: str,
    methods: List[str],
    min_repeats: Optional[int],
    dict_file: Optional[str],
    pinyin_dict_file: Optional[str]
) -> Generator[str, None, None]:
    """
    主生成器函数，根据用户参数协调不同的生成方法。

    1. 获取实际使用的字符集。
    2. 根据选择的 `methods` 准备相应的底层生成器列表。
    3. 使用 `itertools.chain` 连接所有选中的生成器。
    4. 迭代组合后的生成器，进行最终的域名格式校验。
    5. 使用集合 `final_unique_domains` 去重，确保每个域名只 `yield` 一次。

    Args:
        (参数与 main 函数中解析的 args 对应)

    Yields:
        唯一的、符合所有指定条件的域名主体字符串。
    """
    # 步骤 1: 获取字符集和是否允许连字符
    actual_charset = get_charset(chars_arg)
    allow_hyphen = '-' in actual_charset

    # 步骤 2: 准备生成器列表
    generators_to_run: List[Iterable[str]] = []

    if 'all' in methods:
        print(f"  [生成器] 添加: 所有组合 (长度 {length}, 字符集 '{actual_charset}')")
        generators_to_run.append(generate_all_combinations(length, actual_charset))

    if 'dict' in methods:
        if dict_file:
            print(f"  [生成器] 添加: 字典文件 '{dict_file}' (长度 {length}, 字符集 '{actual_charset}')")
            generators_to_run.append(generate_from_file(dict_file, length, actual_charset))
        else:
            # argparse 的校验应该阻止这种情况，但以防万一
            print("警告: 请求使用 'dict' 方法但未提供 --dict-file，已跳过。", file=sys.stderr)

    if 'pinyin' in methods:
        if pinyin_dict_file:
            print(f"  [生成器] 添加: 拼音文件 '{pinyin_dict_file}' (长度 {length}, 字符集 '{actual_charset}')")
            generators_to_run.append(generate_from_file(pinyin_dict_file, length, actual_charset))
        else:
            print("警告: 请求使用 'pinyin' 方法但未提供 --pinyin-dict-file，已跳过。", file=sys.stderr)

    if 'repeats' in methods:
        if min_repeats is not None and min_repeats >= 2:
            print(f"  [生成器] 添加: 重复模式 (长度 {length}, 字符集 '{actual_charset}', 最少重复 {min_repeats})")
            generators_to_run.append(generate_repeating_patterns(length, actual_charset, min_repeats))
        else:
            print(f"警告: 请求使用 'repeats' 方法但 --min-repeats ({min_repeats}) 无效，已跳过。", file=sys.stderr)

    # 步骤 3: 连接所有选择的生成器
    if not generators_to_run:
        print("警告: 没有有效的生成器被选中，扫描将不会产生任何域名。", file=sys.stderr)
        return  # 返回一个空的生成器

    combined_generator = itertools.chain.from_iterable(generators_to_run)

    # 步骤 4 & 5: 迭代、过滤、去重并 Yield
    final_unique_domains: Set[str] = set()  # 用于最终去重
    processed_count = 0  # 跟踪生成器产生的数量（用于调试/感知进度）

    print("  [生成器] 开始处理...")
    for domain_base in combined_generator:
        processed_count += 1
        # a. 检查基本域名格式 (包括连字符规则)
        if is_valid_domain_base(domain_base, allow_hyphen):
            # b. 检查是否已生成过 (去重)
            if domain_base not in final_unique_domains:
                final_unique_domains.add(domain_base)
                yield domain_base  # 产生一个唯一的、有效的域名主体

        # 每处理10000个候选项打印一次进度
        if processed_count % 10000 == 0:
            print(f"  [生成器] 已处理 {processed_count} 个候选项，找到 {len(final_unique_domains)} 个有效候选项...")

    print(f"  [生成器] 处理完成，共找到 {len(final_unique_domains)} 个唯一的有效候选项。")


# --- 主程序入口 ---

def main():
    """解析命令行参数并执行域名扫描。"""
    global MAX_RETRIES  # 移到函数开头

    parser = argparse.ArgumentParser(
        description="灵活扫描 .li 域名可用性。",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  # 在 help 中显示默认值
    )

    # --- 定义命令行参数 ---
    parser.add_argument("-l", "--length", type=int, required=True,
                        help="要扫描的域名主体的长度。")
    parser.add_argument("-c", "--chars",
                        choices=['letters', 'digits', 'alnum',
                                'letters-hyphen', 'digits-hyphen', 'alnum-hyphen'],
                        default='alnum',
                        help="允许的字符集类型:\n"
                             "  letters: 仅小写字母 (a-z)\n"
                             "  digits: 仅数字 (0-9)\n"
                             "  alnum: 字母和数字\n"
                             "  letters-hyphen: 仅字母和连字符 '-'\n"
                             "  digits-hyphen: 仅数字和连字符 '-'\n"
                             "  alnum-hyphen: 字母、数字和连字符 '-' (自动应用连字符规则)")
    parser.add_argument("-m", "--methods", choices=['all', 'dict', 'repeats', 'pinyin'],
                        nargs='+',  # 允许选择一个或多个方法
                        required=True,
                        help="生成域名的方法 (可多选):\n"
                             "  all: 生成所选长度和字符集的所有可能组合。\n"
                             "  dict: 从字典文件中查找符合长度和字符集要求的单词。\n"
                             "  repeats: 生成包含连续重复字符(字母或数字)的组合。\n"
                             "  pinyin: 从拼音字典文件中查找符合条件的拼音。")
    parser.add_argument("--min-repeats", type=int, default=2,
                        help="当方法包含 'repeats' 时，指定最少连续重复字符(字母或数字)的数量 (>=2)。")
    parser.add_argument("--dict-file", type=str, default="/usr/share/dict/words",
                        help="当方法包含 'dict' 时，指定字典文件的路径。")
    parser.add_argument("--pinyin-dict-file", type=str,
                        help="当方法包含 'pinyin' 时，指定拼音字典文件的路径 (例如，每行一个拼音，如 'taobao')。")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help=f"每次 WHOIS 查询之间的延迟时间（秒）。默认: {DEFAULT_DELAY}")
    parser.add_argument("-o", "--output", type=str,
                        help="可选：将找到的可用域名写入指定的文件路径。")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="详细模式：打印每个正在检查的域名的状态。")
    parser.add_argument("--max-retries", type=int, default=MAX_RETRIES,
                        help=f"连接失败时的最大重试次数。默认: {MAX_RETRIES}")

    parser.add_argument("--live-log", type=str,
                        help="指定实时日志文件，可用域名会被立即写入此文件 (可在扫描过程中查看)")

    # --- 解析参数 ---
    args = parser.parse_args()

    # --- 参数依赖性校验 ---
    if 'repeats' in args.methods and (args.min_repeats is None or args.min_repeats < 2):
        parser.error("使用 'repeats' 方法时，--min-repeats 必须指定且 >= 2。")
    if 'dict' in args.methods and not args.dict_file:
        # 即使有默认值，也检查一下以防用户错误地设置为空字符串等
        parser.error("使用 'dict' 方法时，必须提供有效的 --dict-file。")
    if 'pinyin' in args.methods and not args.pinyin_dict_file:
        parser.error("使用 'pinyin' 方法时，必须通过 --pinyin-dict-file 指定文件。")
    if args.length <= 0:
        parser.error("--length 必须是正整数。")

    # 更新全局最大重试次数
    MAX_RETRIES = args.max_retries

    # --- 准备输出文件 (如果指定) ---
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8')
            print(f"结果将写入文件: {args.output}")
        except IOError as e:
            print(f"错误: 无法打开输出文件 '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)  # 决定退出

    # 准备实时日志文件 (如果指定)
    live_log_file = None
    if args.live_log:
        try:
            live_log_file = open(args.live_log, 'w', encoding='utf-8')
            print(f"实时可用域名将写入: {args.live_log}")
        except IOError as e:
            print(f"警告: 无法打开实时日志文件 '{args.live_log}': {e}", file=sys.stderr)
            # 这里只是警告，不终止程序

    # --- 打印扫描配置 ---
    print("\n--- 扫描配置 ---")
    print(f"域名长度: {args.length}")
    actual_charset = get_charset(args.chars)  # 获取实际字符集用于显示
    print(f"字符集类型: {args.chars} (实际使用: '{actual_charset}')")
    print(f"生成方法: {', '.join(args.methods)}")
    if 'repeats' in args.methods: print(f"最小重复数: {args.min_repeats}")
    if 'dict' in args.methods: print(f"字典文件: {args.dict_file}")
    if 'pinyin' in args.methods: print(f"拼音字典: {args.pinyin_dict_file}")
    if args.delay > 0: print(f"查询延迟: {args.delay} 秒")
    else: print("警告: 查询延迟为 0，极易触发频率限制！")
    print(f"最大重试次数: {MAX_RETRIES}")
    print("-" * 18)

    # --- 获取域名生成器 ---
    try:
        print("初始化域名生成器...")
        domain_generator = generate_domains(
            length=args.length,
            chars_arg=args.chars,
            methods=args.methods,
            min_repeats=args.min_repeats,
            dict_file=args.dict_file,
            pinyin_dict_file=args.pinyin_dict_file
        )
    except ValueError as e:  # 捕获 get_charset 可能的错误
        print(f"参数错误: {e}", file=sys.stderr)
        if output_file: output_file.close()  # 关闭已打开的文件
        sys.exit(1)

    # --- 执行扫描循环 ---
    print("\n--- 开始 WHOIS 查询 ---")
    count = 0
    available_count = 0
    rate_limit_hits = 0
    error_hits = 0  # 记录其他错误次数
    start_time = time.time()

    try:
        for domain_base in domain_generator:
            count += 1
            # 调用核心 WHOIS 查询函数
            result = check_li_domain(domain_base)

            # --- 处理并打印结果 ---
            status = result['status']
            status_cn = result['status_cn']
            domain_full = result['domain']

            # 详细模式 或 非"不可用"状态时，打印详细信息
            if args.verbose or status != 'unavailable':
                print(f"[{count}] 查询 {domain_full:<25} ... 状态: {status_cn}")
                # 对特定错误状态打印更详细的原始响应（截断）
                if status in ['rate_limited', 'server_error', 'network_error',
                              'unknown_error', 'invalid_query']:
                    error_hits += 1
                    raw_resp_preview = result['raw_response'].split('\n', 1)[0][:100]
                    if len(result['raw_response']) > 100: raw_resp_preview += '...'
                    print(f"    原始响应/错误: {raw_resp_preview}")

            # --- 特殊状态处理 ---
            if status == 'available':
                available_count += 1
                # 突出显示可用域名
                print(f"  \033[92m-> 找到可用域名: {domain_full}\033[0m")  # 绿色高亮
                # 写入结果文件
                if output_file:
                    output_file.write(f"{domain_full}\n")
                    output_file.flush()  # 立即写入

                # 写入实时日志（带时间戳）
                if live_log_file:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    live_log_file.write(f"[{timestamp}] {domain_full}\n")
                    live_log_file.flush()  # 确保实时写入磁盘

            elif status == 'rate_limited':
                rate_limit_hits += 1
                # 增加暂停时间
                pause_time = args.delay * 5 if args.delay > 0 else 5
                print(f"  \033[93m-> 触发访问频率限制！暂停 {pause_time:.1f} 秒...\033[0m")  # 黄色高亮
                time.sleep(pause_time)

            elif status == 'server_error':
                # 短暂暂停
                pause_time = args.delay * 2 if args.delay > 0 else 2
                print(f"  \033[93m-> 服务器临时错误。暂停 {pause_time:.1f} 秒...\033[0m")
                time.sleep(pause_time)

            # --- 查询延迟 ---
            if args.delay > 0:
                # 在每次查询后（无论结果如何）都应用延迟
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n\033[91m扫描被用户中断 (Ctrl+C)。\033[0m")  # 红色提示
    except Exception as e:
        print(f"\n\033[91m扫描过程中发生意外错误: {e}\033[0m")
    finally:
        # --- 打印总结信息 ---
        end_time = time.time()
        duration = end_time - start_time
        print("\n--- 扫描结果统计 ---")
        print(f"扫描配置:")
        print(f"  长度={args.length}, 字符集={args.chars}, 方法={','.join(args.methods)}")
        print("-" * 20)
        print(f"已检查域名总数:    {count}")
        print(f"找到可用域名数量:  \033[92m{available_count}\033[0m")  # 绿色
        print(f"遇到频率限制次数:  \033[93m{rate_limit_hits}\033[0m")  # 黄色
        print(f"遇到其他错误次数:  \033[91m{error_hits}\033[0m")  # 红色
        print(f"总耗时:            {duration:.2f} 秒")

        # 计算平均速度（避免除零错误）
        if count > 0 and duration > 0.01:  # 避免耗时过短导致速度异常大
            speed = count / duration
            print(f"平均检查速度:      {speed:.2f} 个域名/秒 (包含延迟)")
        elif count > 0:
            print(f"平均检查速度:      N/A (耗时过短)")


        if output_file:
            print(f"可用域名已保存至: {args.output}")
            output_file.close()

        if live_log_file:
            print(f"实时日志已保存至: {args.live_log}")
            live_log_file.close()

        # 输出成功率信息
        if count > 0:
            success_rate = (count - error_hits - rate_limit_hits) / count * 100
            print(f"查询成功率:        {success_rate:.2f}%")

if __name__ == "__main__":
    main()
