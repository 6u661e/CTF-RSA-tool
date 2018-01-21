![](http://oztni9daw.bkt.clouddn.com/e5271927dfd0beac56760e0dcdf81116.png)

# Description

**CTF-RSA-tool** 是一款基于`python`以及`sage`的小工具，可以助CTFer们在CTF比赛中快速解决RSA相关的 **常规题型**

[一张图搞定CTF中的RSA题型](http://naotu.baidu.com/file/503f1eaee72ef304ce687fcbdb1913c6?token=13e96060bd0e02fb)

# Requirements

> TODO

# Installation

> TODO

# Usage examples

> TODO

# How does it work

对于题目给定的一组公钥或n，e，c等变量的值，自动判断应该采用哪种攻击方法，并尝试得到私钥或者明文，从而帮助CTFer快速拿到flag

### 大体思路

- 判断输入

首先，识别用户的输入，可以是证书*pem*文件，也可以通过命令行参数指定n，e，c等变量的值，甚至可以通过命令行指定题目所给的txt文件并自动识别里面的变量

- 判断攻击方法

根据取到的变量有哪些，选取可能成功的方法并采用一定的优先级逐个尝试。

如：题目给了三个变量n，e，c各一个，首先判断e或n的值是否合理，如果不合理，会采用对应的算法解决；如果合理，那么会先尝试在线分解n，然后尝试 *Boneh and Durfee attack* 或 *Wiener’s Attack* 等，如果最后还是不能分解，可能就需要你自己另寻方法了

- 输出

CTFer可以选择输出到文件或打印到终端上，可以选择是输出得到的全部内容还是输出私钥或者明文

### 主要攻击方法

主要参考[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_index.html)上列举出来的RSA一些方法，选取部分常见及易集成的方法

- 模数分解
  - 在线分解N
  - 费马分解（p&q相近时）
  - 模不互素
  - 共模攻击

- 公钥指数攻击
  - 小公钥指数攻击
  - Rabin 算法

- 私钥d攻击
  - d泄露攻击
  - Wiener’s Attack

- Coppersmith Related Attack
  - Basic Broadcast Attack
  - Broadcast Attack with Linear Padding
  - Related Message Attack
  - Coppersmith’s short-pad attack
  - Known High Bits Message Attack
  - Factoring with High Bits Known
  - Boneh and Durfee attack

# Reference

- [ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/crypto/asymmetric/rsa/rsa_index.html)
- [RSA-and-LLL-attacks](https://github.com/mimoo/RSA-and-LLL-attacks)
- [rsa-wiener-attack](https://github.com/pablocelayes/rsa-wiener-attack)
- [rsatool](https://github.com/ius/rsatool)
- [jarvisoj](https://www.jarvisoj.com/)
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)


# Welcome issues

如果你有新的RSA解题思路，欢迎在issues中提出，我看到后会集成进去
