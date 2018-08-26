![](http://oztni9daw.bkt.clouddn.com/e5271927dfd0beac56760e0dcdf81116.png)

# Description

**CTF-RSA-tool** 是一款基于`python`以及`sage`的小工具，助不熟悉RSA的CTFer在CTF比赛中快速解决RSA相关的 **基本题型** 。

# Requirements

- requests
- gmpy2
- pycrypto
- libnum
- sagemath(optional)

# Installation

- 安装libnum

```
git clone https://github.com/hellman/libnum.git
cd libnum
python setup.py install
```

- 安装gmpy2，参考：

`easy_install gmpy2`

如果不行，可以尝试我的安装过程：https://3summer.github.io/2018/01/24/CTF-RSA-tool-install/

- 克隆仓库，安装依赖

```
git clone https://github.com/3summer/CTF-RSA-tool.git
cd CTF-RSA-tool
pip install -r "requirements.txt"
```

- 安装sagemath（非必须）

> 安装sagemath的以支持更多的算法，提高解题成功率，嫌麻烦也可以不安装

官网：http://www.sagemath.org

我的安装过程：https://3summer.github.io/2017/12/06/sage/

# Usage

### 查看全部参数及帮助

`python solve.py -h`

### 列举几个实用的小功能（解题的例子见下面）

- 输入N与e创建公钥

`python solve.py -g --createpub  -N your_modulus -e your_public_exponent -o public.pem`

- 查看密钥文件

`python solve.py -g --dumpkey --key examples/smallfraction.pub`

- 将加密文件转为十进制（方便写入文本，配合`-i`需要）

`python solve.py -g --enc2dec examples/jarvis_oj_hardRSA/flag.enc`

# Examples

> 非 --input（文本文档自动识别攻击） 的情况下，请至少选择 --private（打印得到的私钥） 或 --decrypt（解密一个加密的文件） 或 --decrypt_int（解密一个十进制数） 中的一个，不然程序不会干什么事，具体参考example.txt

大多数情况下，只用使用 `python solve.py -i rsa.txt` 指定一个txt文本，txt的内容为你从题目获取的变量，如

```
n = **********
e = **********
c = **********
```

用`-i`指定这个文本文档就行了，这样就不用用命令行去一个个指定参数，弄的终端看着很乱。
这个txt的编写规范参看`examples/input_example.txt`

# Tips

每次使用都要找到项目目录很麻烦，可以做个符号链接，链接solve.py到bin目录下，如在我的MACos中

`ln -s /Users/3summer/Documents/code/CTF-RSA-tool/solve.py /usr/local/bin/rsa_solve`

之后，就能直接在终端输入`rsa_solve -i rsa.txt`去快速秒简单题了

# How does it work

根据题目给的参数类型，自动判断应该采用哪种攻击方法，并尝试得到私钥或者明文，从而帮助CTFer快速拿到flag或解决其中的RSA考点

### 大体思路

- 判断输入

首先，识别用户的输入，可以是证书 *pem* 文件，也可以通过命令行参数指定`n`，`e`等变量的值，甚至可以通过命令行指定题目所给的txt文件并自动识别里面的变量（见examples）

- 判断攻击方法

根据取到的参数类型及数量，选取可能成功的方法并采用一定的优先级逐个尝试。

如常见的题型：给了一个公钥和一个加密的密文，我们需要先分解大整数N，然后得到私钥再去解密。考点在于大整数分解，脚本会挨个尝试下面 **已实现的攻击方法** 中列举出的关于分解大整数的方法，直到分解成功。

- 选择输出

CTFer可以通过命令行选择是输出私钥还是输出解密后的密文，还是一起输出

### 已实现的攻击方法

主要参考[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_index.html)和[RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)及自己平时遇见的一些题型

- 大整数分解
  - 检查过去的ctf比赛中出现的素数
  - Gimmicky Primes method
  - Wiener's attack
  - factordb在线分解N
  - Small q (q < 100,000)
  - 费马分解（p&q相近时）
  - Boneh Durfee Method (d < n^0.292)
  - Small fractions method when p/q is close to a small fraction

- Basic Broadcast Attack
- Known High Bits Factor Attack
- Common factor between ciphertext and modulus attack
- 小公钥指数攻击
- Rabin 算法
- 模不互素
- 共模攻击
- d泄露攻击

# Reference

- [ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_index.html)
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
- [jarvisoj](https://www.jarvisoj.com/)
- [RSA-and-LLL-attacks](https://github.com/mimoo/RSA-and-LLL-attacks)
- [rsa-wiener-attack](https://github.com/pablocelayes/rsa-wiener-attack)
- [rsatool](https://github.com/ius/rsatool)


# TODO

- 更多有关Coppersmith的攻击
    - https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_coppersmith_attack.html
    - http://inaz2.hatenablog.com/entries/2016/01/20

- 改善RsaCtfTool中几个没加进去的方法（我觉得不太ok的暂时没加进来）
    - https://github.com/Ganapati/RsaCtfTool

- 寻找更多题型来丰富攻击方法
    - google
    - github
    - baidu
    - ......
