# coding:utf-8
from Crypto.PublicKey import RSA
from Crypto.PublicKey import _slowmath
import gmpy2
from functools import reduce
import libnum
import subprocess
import os
import logging
logging.basicConfig(format='\033[92m%(levelname)s\033[0m: %(message)s')
log = logging.getLogger()
log.setLevel(logging.INFO)
import factor_N


class RSAAttack(object):
    def __init__(self, args):
        self.args = args
        if self.args.verbose:
            log.setLevel(logging.DEBUG)
        self.n = args.N or None
        self.e = args.e or None
        self.p = args.p or None
        self.q = args.q or None
        self.d = args.d or None
        # high bits of factor
        self.hbop = args.KHBFA or None
        self.pbits = args.pbits or None
        self.sageworks = args.sageworks
        self.data = args.data or None
        # 是否需要解密密文
        if self.args.decrypt:
            with open(self.args.decrypt, 'r') as f:
                self.c = libnum.s2n(f.read().strip())
        elif self.args.decrypt_int:
            self.c = self.args.decrypt_int
        else:
            self.c = None

    def attack(self):

        # 下面是需要多组密钥的攻击方法
        if self.args.multiple:
            if 'd' in self.data:
                # d泄漏攻击，获得d并继续下面进行解密
                self.d, self.p, self.q = d_leak(
                    self.data['n'], self.data['e'][0], self.data['d'], self.data['e'][1])
                self.e = self.data['e'][1]
            else:
                # 模不互素
                if isinstance(self.data['n'], list) and isinstance(self.data['e'], long) and isinstance(self.data['c'], long):
                    share_factor(
                        self.data['n'][0], self.data['n'][1], self.data['e'], self.data['c'])
                    return
                # 共模攻击
                if isinstance(self.data['n'], long) and isinstance(self.data['e'], list) and isinstance(self.data['c'], list):
                    share_N(self.data['n'], self.data['e'][0], self.data['e']
                            [1], self.data['c'][0], self.data['c'][1])
                    return
                # Basic Broadcast Attack
                if isinstance(self.data['n'], list) and isinstance(self.data['e'], long) and isinstance(self.data['c'], list):
                    Basic_Broadcast_Attack(self.data)
                    return

        # 下面是只需要一组密钥的攻击

        # 是否通过--input输入参数，此时args.data应该是单组密钥
        if self.data:
            try:
                self.n = self.n or self.data['n']
                self.e = self.e or self.data['e']
                self.c = self.c or (
                    self.data['c'] if 'c' in self.data else None)
                self.d = self.d or (
                    self.data['d'] if 'd' in self.data else None)
                self.p = self.p or (
                    self.data['p'] if 'p' in self.data else None)
                self.q = self.q or (
                    self.data['q'] if 'q' in self.data else None)
                self.hbop = self.hbop or (
                    self.data['hbop'] if 'hbop' in self.data else None)
                self.pbits = self.pbits or (
                    self.data['pbits'] if 'pbits' in self.data else None)
            except Exception as e:
                log.error('please check your --input')
                print e
                return
        else:
            # 通过命令行参数读取，得到N与e，没有的话抛出异常
            try:
                if self.args.key:
                    key = open(self.args.key, 'r').read()
                    pub = RSA.importKey(key)
                    self.n = pub.n
                    self.e = pub.e
                else:
                    self.n = self.args.N
                    self.e = self.args.e
            except Exception:
                log.error('please input right --key or -N and -e')
                return

        # 判断是否为小公钥指数攻击
        # if self.e > 2 and self.e <= 11 and self.c is not None:
        if self.e > 2 and self.e <= 10 and self.c is not None:
            hastads(self.n, self.e, self.c)
            return

        # 判读是否为Known High Bits Factor Attack
        if self.hbop:
            if not self.sageworks:
                log.error('please install sage first')
                return
            if self.pbits:
                sageresult = int(subprocess.check_output(
                    ['sage', os.path.dirname(__file__)+ '/KnownHighBitsFactorAttack.sage', str(self.n), str(self.hbop), str(self.pbits)]))
            else:
                sageresult = int(subprocess.check_output(
                    ['sage', os.path.dirname(__file__)+ '/KnownHighBitsFactorAttack.sage', str(self.n), str(self.hbop)]))
            if sageresult > 0:
                self.p = sageresult
                self.q = self.n / self.p
                self.d = libnum.invmod(self.e, (self.p - 1) * (self.q - 1))

        # 如果没有提供d
        if not self.d:
            # 分解大整数n
            factors = factor_N.solve(self.n, self.e, self.c, self.sageworks)
            if factors:
                self.p, self.q = factors

            # 判断是否为RABIN算法
            if self.e == 2:
                if not self.c:
                    log.error('rabin: please offer cipher')
                    return
                if self.p and self.q:
                    rabin(self.n, self.c, self.p, self.q)
                else:
                    log.error('rabin: can not factor N, please offer p and q')
                return

            # 分解得到p q，或用户输入了p和q，计算d
            if self.p and self.q:
                self.d = libnum.invmod(self.e, (self.p - 1) * (self.q - 1))
                log.debug('d = ' + hex(self.d))
            else:
                log.error('can not factor N, please offer p and q or d')
                return

        # --private 是否需要打印私钥
        if self.args.private:
            log.info('\np=%d\nq=%d\nd=%d\n' % (self.p, self.q, self.d))
            log.info('private key:\n' + RSA.construct((long(self.n), long(self.e),
                                                       long(self.d), long(self.p), long(self.q))).exportKey())

        # 不需要解密，直接返回
        if not self.c:
            return
        self.plain = pow(self.c, self.d, self.n)
        # 打印解密出来的明文
        log.info(libnum.n2s(self.plain))


# d泄露攻击，根据过期的(N，e1，d1)，和一个新的e2，返回d2
def d_leak(N, e1, d1, e2):
    p, q = nde_2_pq(N, d1, e1)
    return libnum.invmod(e2, (p - 1) * (q - 1)), p, q


def nde_2_pq(N, d, e):
    tmp_priv = _slowmath.rsa_construct(long(N), long(e), d=long(d))
    p = tmp_priv.p
    q = tmp_priv.q
    return p, q


# 模不互素: 需要（n1，e1，c1）及（n2，e2），且e1 == e2。解密c1
def share_factor(n1, n2, e, c1):
    p1 = gmpy2.gcd(n1, n2)
    q1 = n1 / p1
    d = gmpy2.invert(e, (p1 - 1) * (q1 - 1))
    plain = gmpy2.powmod(c1, d, n1)
    plain = hex(plain)[2:]
    if len(plain) % 2 != 0:
        plain = '0' + plain
    log.info('Here are your plain text: \n' + plain.decode('hex'))


# 共模攻击: 需要（n1，e1，c1）及（n2，e2, c2），且n1 == n2 and gcd(e1,e2) == 1。
def share_N(N, e1, e2, c1, c2):
    gcd, s, t = gmpy2.gcdext(e1, e2)
    if s < 0:
        s = -s
        c1 = gmpy2.invert(c1, N)
    if t < 0:
        t = -t
        c2 = gmpy2.invert(c2, N)
    plain = gmpy2.powmod(c1, s, N) * gmpy2.powmod(c2, t, N) % N
    log.info('Here are your plain text: \n' + libnum.n2s(plain))


# e=2，rabin算法
def rabin(N, c, p, q):
    inv_p = libnum.invmod(p, q)
    inv_q = libnum.invmod(q, p)

    mp = pow(c, (p + 1) / 4, p)
    mq = pow(c, (q + 1) / 4, q)

    a = (inv_p * p * mq + inv_q * q * mp) % N
    b = N - int(a)
    c = (inv_p * p * mq - inv_q * q * mp) % N
    d = N - int(c)

    for i in (a, b, c, d):
        s = '%x' % i
        if len(s) % 2 != 0:
            s = '0' + s
        log.info('Here are your plain text: \n' + s.decode('hex'))


# Hastad attack for low public exponent, this has found success for e = 3, and e = 5 previously
def hastads(N, e, c):
    log.info(
        'start Hastad attack. If there was no result after a long time. Press ctrl+c to stop, and try other ways.')
    n = 0
    while True:
        if gmpy2.iroot(c + n * N, e)[1]:
            log.info('Here are your plain text: \n' +
                     libnum.n2s(gmpy2.iroot(c + n * N, e)[0]))
            return
        n += 1


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return int(sum % prod)


def modinv(a, m):
    return int(gmpy2.invert(gmpy2.mpz(a), gmpy2.mpz(m)))


def Basic_Broadcast_Attack(data):
    if data['e'] == len(data['n']) == len(data['c']):
        t_to_e = chinese_remainder(data['n'], data['c'])
        t = int(gmpy2.iroot(t_to_e, data['e'])[0])
        log.info('Here are your plain text: \n' + libnum.n2s(t))
    else:
        log.error('wrong json file, check examples')


if __name__ == '__main__':
    pass
