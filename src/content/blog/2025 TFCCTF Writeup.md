---
title: 2025 TFCCTF Writeup
publishDate: 2025-09-01
description: '打打停停，勉强排在#22'
heroImage: {src: 'https://pic.swizzer.cc/2025/09/4630895136cf1924bdbeed295e1642c3.png', inferSize: true}
tags: ["CTF", "Misc", "Crypto", "Jail", "Lattice"]
category: 'Writeups'
draft: false 
lang: ''
---
难得碰上一次全数主力~~5个人~~都上线的比赛。不过因为开学选课等等事务，感觉最终也就发挥了七成😶‍🌫️

惯例先贴队友的WP

[some Web challenges solved by @cheng_xing](https://sakuraraindrop.github.io/2025/08/29/TFCCTF-2025/)

# Misc
## Mini Jail

> [题目附件](https://pic.swizzer.cc/2025/09/minijail.zip)

乍一看跟探姬之前搞的[Bashfuck](https://github.com/ProbiusOfficial/bashFuck)很像，不过可用字符集更少。

因为反斜杠被ban了+flag文件名是随机的，所以我猜预期解肯定不是`cat flag*`这种东西，毕竟构造起来太难了。而且flag文件名随机往往暗示着可以直接拿到无限制的shell，因此我的思路就是构造出`sh`去拿shell。

对着探姬给的资料研究了研究发现在这题中可以用`$((!_))`造出来`1`，然后就能造出来`$1`。检查本题的Dockerfile可以知道`$1`拿到的是`yooooooo_mama_test`，然后反复利用切片操作可以拿到`s`。`sh`里还缺个`h`，这个可以通过对`echo`切片拿到，而`echo`用`${_}`就能构造出来。

综合起来可以构造出以下payload，逐行执行即可拿到`sh` shell：

```sh
___=${_}
__=$((!_))
____=${!__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
____=${____:$__}
___=${___:$__}
___=${___:$__}
${____:$((!__)):$__}${___:$((!__)):$__}
```

~~可以发现这样搞出来甚至不需要重定向符号，所以题目给的字符集其实还不够紧~~当然如果肯用重定向符号可以把payload行数压缩到两行

## Blackbox

给了个固件，直接`readelf`能得到

```txt collapse={1-155}
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Atmel AVR 8-bit microcontroller
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          8164 (bytes into file)
  Flags:                             0x5, avr:5
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         3
  Size of section headers:           40 (bytes)
  Number of section headers:         14
  Section header string table index: 11

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .data             PROGBITS        00800100 000378 00004e 00  WA  0   0  1
  [ 2] .text             PROGBITS        00000000 000094 0002e4 00  AX  0   0  2
  [ 3] .bss              NOBITS          0080014e 0003c6 000009 00  WA  0   0  1
  [ 4] .comment          PROGBITS        00000000 0003c6 000011 01  MS  0   0  1
  [ 5] .note.gnu.av[...] NOTE            00000000 0003d8 000040 00      0   0  4
  [ 6] .debug_aranges    PROGBITS        00000000 000418 000060 00      0   0  8
  [ 7] .debug_info       PROGBITS        00000000 000478 0007f5 00      0   0  1
  [ 8] .debug_abbrev     PROGBITS        00000000 000c6d 0005de 00      0   0  1
  [ 9] .debug_line       PROGBITS        00000000 00124b 00019a 00      0   0  1
  [10] .debug_str        PROGBITS        00000000 0013e5 000208 00      0   0  1
  [11] .shstrtab         STRTAB          00000000 001f56 00008e 00      0   0  1
  [12] .symtab           SYMTAB          00000000 0015f0 000580 10     13  28  4
  [13] .strtab           STRTAB          00000000 001b70 0003e6 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)

There are no section groups in this file.

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000094 0x00000000 0x00000000 0x002e4 0x002e4 R E 0x2
  LOAD           0x000378 0x00800100 0x000002e4 0x0004e 0x0004e RW  0x1
  LOAD           0x0003c6 0x0080014e 0x0080014e 0x00000 0x00009 RW  0x1

 Section to Segment mapping:
  Segment Sections...
   00     .text 
   01     .data 
   02     .bss 

There is no dynamic section in this file.

There are no relocations in this file.

The decoding of unwind sections for machine type Atmel AVR 8-bit microcontroller is not currently supported.

Symbol table '.symtab' contains 88 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00800100     0 SECTION LOCAL  DEFAULT    1 .data
     2: 00000000     0 SECTION LOCAL  DEFAULT    2 .text
     3: 0080014e     0 SECTION LOCAL  DEFAULT    3 .bss
     4: 00000000     0 SECTION LOCAL  DEFAULT    4 .comment
     5: 00000000     0 SECTION LOCAL  DEFAULT    5 .note.gnu.avr.de[...]
     6: 00000000     0 SECTION LOCAL  DEFAULT    6 .debug_aranges
     7: 00000000     0 SECTION LOCAL  DEFAULT    7 .debug_info
     8: 00000000     0 SECTION LOCAL  DEFAULT    8 .debug_abbrev
     9: 00000000     0 SECTION LOCAL  DEFAULT    9 .debug_line
    10: 00000000     0 SECTION LOCAL  DEFAULT   10 .debug_str
    11: 00000000     0 FILE    LOCAL  DEFAULT  ABS 
    12: 0000003e     0 NOTYPE  LOCAL  DEFAULT  ABS __SP_H__
    13: 0000003d     0 NOTYPE  LOCAL  DEFAULT  ABS __SP_L__
    14: 0000003f     0 NOTYPE  LOCAL  DEFAULT  ABS __SREG__
    15: 00000000     0 NOTYPE  LOCAL  DEFAULT  ABS __tmp_reg__
    16: 00000001     0 NOTYPE  LOCAL  DEFAULT  ABS __zero_reg__
    17: 000000d4    14 FUNC    LOCAL  DEFAULT    2 _ZL2z1v
    18: 00800153     4 OBJECT  LOCAL  DEFAULT    3 timer0_millis
    19: 00800152     1 OBJECT  LOCAL  DEFAULT    3 timer0_fract
    20: 0080014e     4 OBJECT  LOCAL  DEFAULT    3 timer0_overflow_count
    21: 00000068    45 OBJECT  LOCAL  DEFAULT    2 _ZL2Xf
    22: 00800100    78 OBJECT  LOCAL  DEFAULT    1 CSWTCH.14
    23: 00000000     0 FILE    LOCAL  DEFAULT  ABS _clear_bss.o
    24: 000000c2     0 NOTYPE  LOCAL  DEFAULT    2 .do_clear_bss_start
    25: 000000c0     0 NOTYPE  LOCAL  DEFAULT    2 .do_clear_bss_loop
    26: 00000000     0 FILE    LOCAL  DEFAULT  ABS _exit.o
    27: 000002e2     0 NOTYPE  LOCAL  DEFAULT    2 __stop_program
    28: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_22
    29: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_1
    30: 0000ffa0     0 NOTYPE  GLOBAL DEFAULT  ABS __DATA_REGION_LE[...]
    31: 00000068     0 NOTYPE  GLOBAL DEFAULT    2 __trampolines_start
    32: 000002e4     0 NOTYPE  GLOBAL DEFAULT    2 _etext
    33: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_24
    34: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_12
    35: 000000d0     0 NOTYPE  GLOBAL DEFAULT    2 __bad_interrupt
    36: 00000332     0 NOTYPE  GLOBAL DEFAULT  ABS __data_load_end
    37: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_6
    38: 00000068     0 NOTYPE  GLOBAL DEFAULT    2 __trampolines_end
    39: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_3
    40: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_23
    41: 000002e4     0 NOTYPE  GLOBAL DEFAULT  ABS __data_load_start
    42: 00000096     0 NOTYPE  GLOBAL DEFAULT    2 __dtors_end
    43: 00800157     0 NOTYPE  GLOBAL DEFAULT    3 __bss_end
    44: 00000400     0 NOTYPE  GLOBAL DEFAULT  ABS __LOCK_REGION_LE[...]
    45: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_25
    46: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_11
    47: 00000096     0 NOTYPE  WEAK   DEFAULT    2 __init
    48: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _Z14serialEventRunv
    49: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_13
    50: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_17
    51: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_19
    52: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_7
    53: 000000b8    16 NOTYPE  GLOBAL HIDDEN     2 __do_clear_bss
    54: 00810000     0 NOTYPE  GLOBAL DEFAULT    4 __eeprom_end
    55: 00000000     0 NOTYPE  GLOBAL DEFAULT    2 __vectors
    56: 0080014e     0 NOTYPE  GLOBAL DEFAULT    1 __data_end
    57: 00000000     0 NOTYPE  WEAK   DEFAULT    2 __vector_default
    58: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_5
    59: 00000400     0 NOTYPE  GLOBAL DEFAULT  ABS __SIGNATURE_REGI[...]
    60: 00000096     0 NOTYPE  GLOBAL DEFAULT    2 __ctors_start
    61: 000000a2    22 NOTYPE  GLOBAL HIDDEN     2 __do_copy_data
    62: 0080014e     0 NOTYPE  GLOBAL DEFAULT    3 __bss_start
    63: 00000176   362 FUNC    GLOBAL DEFAULT    2 main
    64: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_4
    65: 00000000     0 NOTYPE  WEAK   DEFAULT  ABS __heap_end
    66: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_9
    67: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_2
    68: 00000400     0 NOTYPE  GLOBAL DEFAULT  ABS __USER_SIGNATURE[...]
    69: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_21
    70: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_15
    71: 00000096     0 NOTYPE  GLOBAL DEFAULT    2 __dtors_start
    72: 00000096     0 NOTYPE  GLOBAL DEFAULT    2 __ctors_end
    73: 000008ff     0 NOTYPE  WEAK   DEFAULT  ABS __stack
    74: 0080014e     0 NOTYPE  GLOBAL DEFAULT    1 _edata
    75: 00800157     0 NOTYPE  GLOBAL DEFAULT    4 _end
    76: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_8
    77: 000002e0     0 NOTYPE  WEAK   HIDDEN     2 exit
    78: 00010000     0 NOTYPE  GLOBAL DEFAULT  ABS __EEPROM_REGION_[...]
    79: 000002e0     0 NOTYPE  GLOBAL HIDDEN     2 _exit
    80: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_14
    81: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_10
    82: 000000e2   148 FUNC    GLOBAL DEFAULT    2 __vector_16
    83: 00800100     0 NOTYPE  GLOBAL DEFAULT    1 __data_start
    84: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_18
    85: 00000003     0 NOTYPE  GLOBAL DEFAULT  ABS __FUSE_REGION_LE[...]
    86: 00020000     0 NOTYPE  GLOBAL DEFAULT  ABS __TEXT_REGION_LE[...]
    87: 000000d0     0 NOTYPE  WEAK   DEFAULT    2 __vector_20

No version information found in this file.

Displaying notes found in: .note.gnu.avr.deviceinfo
  Owner                Data size        Description
  AVR                  0x0000002d       NT_VERSION (version)
   description data: 00 00 00 00 00 80 00 00 00 01 00 00 00 08 00 00 00 00 00 00 00 04 00 00 08 00 00 00 01 00 00 00 00 61 74 6d 65 67 61 33 32 38 70 00 00 
```

喂给AI得知这是AVR 8 位单片机的固件。在Arch Linux上执行`paru -S simavr`装好对应固件的工具链，然后`avr-objdump -d -S firmware.elf > output.asm`可以得到对应的汇编。

简单看了看似乎是个驱动7段数码管显示东西的代码，里面是个简单的异或加密。直接提出来数据异或回去就能拿到flag

```python title="solve.py"
data = bytes.fromhex("f1 e3 e6 e6 f1 e3 de f1 cd 94 d6 fa 94 d6 fa d6 ca c8 96 fa d6 94 c8 d5 c9 96 fa 91 d7 c1 d0 94 cb ca fa c3 94 d7 c8 d2 91 d7 c0 d8 00 00".replace(" ",""))
decoded = bytes([b ^ 0xA5 for b in data])
decoded, decoded.decode('latin1')
```

## TO ROTATE, OR NOT TO ROTATE
交互式题目，给了个 3x3 点阵的棋盘，取满足 `gcd(dx, dy) == 1`的线段，一共28条。我们的每组提交也是一堆线段，然后题目会在 **0/90/180/270°** 旋转下根据这28条合法线段的位置把我们提交的线段计算成28bits，并取数值最小的那个作为这组线段的`canon_bits(segs)`。

交互流程分两阶段、总共 Q 轮（题目附件里 Q=120，但是靶机里Q=1000，逆天完了）

- **Phase 1**：服务器给出随机 `N_i`，选手提交一组线段；程序计算 `c_i = canon_bits(segs)`，建立映射 `canon2N[c_i] = N_i`。
- **Phase 2**：服务器把 Phase 1 提交的每组线段做整体随机旋转、随机交换端点顺序、并乱序排列，发回作为 `MutatedPattern`，我们需要回答其对应的 `N`。

我的思路很简单，就是在28条线段里随机抽几条然后计算`c = canon_bits(segs)`，如果 `c` 出现过就重抽。这样在Phase 2里通过查表就能搞定。

exp是AI写的且很长，就不贴了。

> 逆天主办方最初给的靶机时长只有7分半，坐在中国跟欧洲服务器搞2000轮交互无论如何都极难在7分半之内完成。去dc跟主办方battle了之后他们才勉强放宽到10min的时长限制。

# Crypto
## WHY THE BEAR HAS NO TAIL

```python title="server.py"
import random

# from secret_stuff import FLAG
FLAG = "TFCCTF{test}TFCCTF{test}TFCCTF{test}TFCCTF{test}TFCCTF{test}TFCCTF{test}TFCCTF{test}TFCCTF{test"


class Challenge:
  def __init__(self):
    self.n = 2**26
    self.k = 2000
    # self.words = [i for i in range(n)]
    # self.buf = random.choices(self.words, k=k)
    self.index = 0

  def get_sample(self):
    self.index += 1
    if self.index > self.k:
      print("Reached end of buffer")
    else:
      print(
        "uhhh here is something but idk what u finna do with it: ",
        random.choices(range(self.n), k=1)[0],
      )

  def get_flag(self):
    idxs = [i for i in range(256)]
    key = random.choices(idxs, k=len(FLAG))
    omlet = [ord(FLAG[i]) ^ key[i] for i in range(len(FLAG))]
    print("uhh ig I can give you this if you really want it... chat?", omlet)

  def loop(self):
    while True:
      print("what you finna do, huh?")
      print("1. guava")
      print("2. muava")
      choice = input("Enter your choice: ")
      if choice == "1":
        self.get_sample()
      elif choice == "2":
        self.get_flag()
      else:
        print("Invalid choice")


if __name__ == "__main__":
  c = Challenge()
  c.loop()
```

一眼MT19937，不过去`cpython/Lib/random.py`里翻了翻没看到`Random`类下面的`random()`函数，只看到`SystemRandom`类下面有这个函数。

如果真的是`SystemRandom`那就没法打了。问了问AI，AI说`Random`类下面的`random()`函数在默认情况下生成的是53bit精度的浮点数，是先后调用了两次`getrandbits()`生成`A`和`B`(`A`是`getrandbits(27)`，`B`是`getrandbits(26)`)，最终把`(A<<26+B)/2**53`输出。

题目用的`choices()`在不传入weights参数的情况下输出的是`floor(random()*n)`，题目里`n`是`2**26`，所以取整后输出的其实就是`A>>1`,相当于`getrandbits(26)`。

那么我们每轮交互能收集到26bits的`getrandbits()`，后续直接可以一把梭。

```python title="solve.py"
from tqdm import trange
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from pwn import *

context.log_level = "debug"
def mt19937(bs, out):
  lin = LinearSystem([32] * 624)
  mt = lin.gens()
  rng = MT19937(mt)
  zeros = []
  for o in out:
    zeros.append(rng.getrandbits(bs) ^ int(o))
    rng.getrandbits(32)
  zeros.append(mt[0] ^ int(0x80000000))
  sol = lin.solve_one(zeros)
  rng = MT19937(sol)
  pyrand = rng.to_python_random()
  return pyrand

# ncat --ssl the-bear-591b845c973a2fa6.challs.tfcctf.com 1337
conn = remote("the-bear-591b845c973a2fa6.challs.tfcctf.com", 1337, ssl=True)
# conn = process(["python", "challenge.py"])
out = []
nums = 1250
for _ in trange(nums):
  conn.recvuntil(b"Enter your choice: ")
  conn.sendline(b"1")
  out.append(int(conn.recvline().strip().split(b": ")[-1].decode()))


RNG = mt19937(26, out)
prev = [RNG.getrandbits(32) for _ in range(nums * 2)]
xors = RNG.choices(range(256), k=95)
log.success(f"xors: {xors}")
conn.recvuntil(b"Enter your choice: ")
conn.sendline(b"2")
# conn.recvline()
check = eval(conn.recvline().strip().split(b"? ")[-1])
print(f"[*] check: {check}")

for a, b in zip(check, xors):
  print(chr(a ^ b), end="")
```

## DEEZ ERRORZ

```python title="chall.sage"
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random
from secret import flag

mod = 0x225fd
flag = bytes_to_long(flag)
e_values = [97491, 14061, 55776]
S = (lambda f=[flag], sk=[]: ([sk.append(f[0] % mod) or f.__setitem__(0, f[0] // mod) for _ in iter(lambda: f[0], 0)],sk)[1])()
S = vector(GF(mod), S)

A_save = []
b_save = []

for i in range(52):
    A = VectorSpace(GF(mod), 44).random_element()
    e = random.choice(e_values)
    b = A * S + e
    #print(b)

    A_save.append(A)
    b_save.append(b)

open('out.txt', 'w').write('A_values = ' + str(A_save) + ' ; b_values = ' + str(b_save))
```

经典LWE，e从给定的三值里随机选择。e不算小所以直接格是格不出来的，不过本题里的e可以找到个线性变换把它们变到(1,-1,0)，然后就能格了。

思路跟鸡块出过的[east_mod_X](https://tangcuxiaojikuai.xyz/post/94c7e291.html)完全一样。

```python title="solve.py"
from sage.all import *
from Crypto.Util.number import *


def primal_attack(A, b, m, n, p):
  L = block_matrix(
    [
      [matrix(Zmod(p), A).T.echelon_form().change_ring(ZZ), 0],
      [matrix.zero(m - n, n).augment(matrix.identity(m - n) * p), 0],
      [matrix(ZZ, b), 1],
    ]
  )
  L = L.BKZ(block_size=20)
  res = L[0]
  if res[-1] == 1:
    e2 = res[:-1]
  else:
    e2 = -res[:-1]
  return e2

# fmt:off
A_values = ...
b_values = ...
e_values = ...
# fmt:on
A = Matrix(ZZ, A_values)
b = vector(ZZ, b_values)
p = 0x225FD
k = 118983
t = 70787
e_ = primal_attack(k * A, (k * b + vector(Zmod(p), [t] * len(b))), 52, 44, p)
e = inverse(k, p) * (e_ - vector(Zmod(p), [t] * len(b)))
s = [int(c) for c in A.solve_right(b - e)]
print(s)
flag = sum(d * pow(p, i) for i, d in enumerate(s))
print(long_to_bytes(flag).decode())
```

# Afterstory

赛中逆向大跌all in了misc里的那题`CREAKYVAULT`，前面的校验绕了个七七八八可惜到最后棋差一着不知道怎么绕过最终读取文件时的URI校验，遗憾离场。||顺带也导致我们的逆向除了签到题就爆零了||

密码那题`MINI AURA`完全不知道哪里是密码，队内Pwn大跌用qemu嗯调嗯逆了大半天做出来的，结果赛后看SU的题解直接用Ghidra+插件就反汇编出来了👿

> 这个插件[@oldkingOK](https://oldkingok.cc/)早就找着了，但是他那边测下来完全反汇编不出来这题

`Mini Jail`那题头天晚上看的时候想出来了切出`s`的方法，但是没想到怎么切出来`h`；第二天离完赛还有半小时的时候上号又看了看，最后赶在结束前8min才做出来🥹

因为密码里的逆向太多直接给[@doctxing](https://let.doctxing.win/)搞破防了，第二天他直接下机去学抽代了2333

> 感觉如果再合理分配一点任务，应该有机会打进前15的，不过最终拿到第22也已经心满意足啦