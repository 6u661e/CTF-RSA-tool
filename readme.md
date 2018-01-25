![](http://oztni9daw.bkt.clouddn.com/e5271927dfd0beac56760e0dcdf81116.png)

# Description

**CTF-RSA-tool** 是一款基于`python`以及`sage`的小工具，可以助CTFer们在CTF比赛中快速解决RSA相关的 **基本题型** 。

~~不懂RSA的小白说(hai)不(shi)定(yao)也(hao)能(hao)拿(xue)一(xi)血(a)。~~

[一张图搞定CTF中的RSA题型](http://naotu.baidu.com/file/503f1eaee72ef304ce687fcbdb1913c6?token=13e96060bd0e02fb)

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

https://www.cnblogs.com/pcat/p/5746821.html

> 原文里面安装MPFR的地址404了，需要去官网获取最新的，安装失败的可以参考我的博客

https://d001um3.github.io/2018/01/24/CTF-RSA-tool-install/

- 克隆仓库，安装依赖

```
git clone https://github.com/D001UM3/CTF-RSA-tool.git
cd CTF-RSA-tool
pip install -r "requirements.txt"
```

- 安装sagemath

> 安装sagemath的以获得更高的成功率，建议安一个，嫌麻烦也可以不安装

官网：http://www.sagemath.org

不会安装的可以看我博客：https://d001um3.github.io/2017/12/06/sage/

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

> 非 --input（文本文档自动识别攻击） 的情况下，请至少选择 --private（打印得到的私钥） 或 --decrypt（解密一个加密的文件） 或 --decrypt_int（解密一个十进制数） 中的一个，不然程序不会干什么事

### 只需要一组密钥的

> 我这里‘组’的意思是有几个模数N或指数e等

- Wiener's attack

`python solve.py --verbose --private -i examples/wiener_attack.txt`

>或者通过命令行，只要指定对应参数就行了

`python solve.py  --verbose --private -N 460657813884289609896372056585544172485318117026246263899744329237492701820627219556007788200590119136173895989001382151536006853823326382892363143604314518686388786002989248800814861248595075326277099645338694977097459168530898776007293695728101976069423971696524237755227187061418202849911479124793990722597 -e 354611102441307572056572181827925899198345350228753730931089393275463916544456626894245415096107834465778409532373187125318554614722599301791528916212839368121066035541008808261534500586023652767712271625785204280964688004680328300124849680477105302519377370092578107827116821391826210972320377614967547827619`

- 利用 factordb.com 分解大整数

`python solve.py --verbose  -k examples/jarvis_oj_mediumRSA/pubkey.pem --decrypt examples/jarvis_oj_mediumRSA/flag.enc`

- Boneh and Durfee attack

> TODO: get an example public key solvable by boneh_durfee but not wiener

- small q attack

`python solve.py --verbose --private -k examples/small_q.pub`

- 费马分解（p&q相近时）

`python solve.py --verbose --private -i examples/closed_p_q.txt`

- Common factor between ciphertext and modulus attack（密文与模数不互素）

`python solve.py --verbose -k examples/common_factor.pub --decrypt examples/common_factor.cipher --private`

- small e

`python solve.py --verbose -k examples/small_exponent.pub  --decrypt examples/small_exponent.cipher`

- Rabin 算法 （e == 2）

`python solve.py --verbose -k examples/jarvis_oj_hardRSA/pubkey.pem --decrypt examples/jarvis_oj_hardRSA/flag.enc`

- Small fractions method when p/q is close to a small fraction

`python solve.py --verbose -k examples/smallfraction.pub  --private`

- Known High Bits Factor Attack

`python solve.py --verbose --private -i examples/KnownHighBitsFactorAttack.txt`


### 需要多组密钥的

- d泄漏攻击

`python solve.py --verbose --private -i examples/d_leak.txt`

- 模不互素

`python solve.py --verbose --private -i examples/share_factor.txt`

- 共模攻击

`python solve.py --verbose --private -i examples/share_N.txt`

- Basic Broadcast Attack

`python solve.py --verbose --private -i examples/Basic_Broadcast_Attack.txt`

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

主要参考[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_index.html)和[RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)

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
