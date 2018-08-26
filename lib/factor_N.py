# coding:utf-8
import requests
import re
from Crypto.PublicKey import _slowmath
import subprocess
import libnum
import RSAutils
import signal
import os


log = RSAutils.log


def solve(N, e, c, sageworks):
    if sageworks:
        return pastctfprimes(N) or noveltyprimes(N) or wiener_attack(N, e) or factordb(N) or comfact_cn(N, c) or smallq(N) or p_q_2_close(N) or boneh_durfee(N, e) or smallfraction(N) or None
    else:
        return pastctfprimes(N) or noveltyprimes(N) or wiener_attack(N, e) or factordb(N) or comfact_cn(N, c) or smallq(N) or p_q_2_close(N) or None


class timeout:
    def __init__(self, seconds=10, error_message='[-] Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise FactorizationError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


class FactorizationError(Exception):
    pass


def factordb(N):
    # if factordb returns some math to derive the prime, solve for p without using an eval
    def solveforp(equation):
        try:
            if '^' in equation:
                k, j = equation.split('^')
            if '-' in j:
                j, sub = j.split('-')
            eq = map(int, [k, j, sub])
            return pow(eq[0], eq[1]) - eq[2]
        except Exception as e:
            log.debug("FactorDB gave something we couldn't parse sorry (%s). Got error: %s" % (equation, e))
            raise FactorizationError()

    # Factors available online?
    try:
        url_1 = 'http://www.factordb.com/index.php?query=%i'
        url_2 = 'http://www.factordb.com/index.php?id=%s'
        s = requests.Session()
        r = s.get(url_1 % N)
        regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
        ids = regex.findall(r.text)
        p_id = ids[1]
        q_id = ids[2]
        regex = re.compile("value=\"([0-9\^\-]+)\"", re.IGNORECASE)
        r_1 = s.get(url_2 % p_id)
        r_2 = s.get(url_2 % q_id)
        key_p = regex.findall(r_1.text)[0]
        key_q = regex.findall(r_2.text)[0]
        p = int(key_p) if key_p.isdigit() else solveforp(key_p)
        q = int(key_q) if key_q.isdigit() else solveforp(key_q)
        if p == q == N:
            raise FactorizationError()
        return p, q
    except Exception:
        return


def noveltyprimes(N):
    log.debug('factor N: try Gimmicky Primes method')
    # "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070"
    # not all numbers in this form are prime but some are (25 digit is prime)
    maxlen = 25  # max number of digits in the final integer
    for i in range(maxlen - 4):
        prime = long("3133" + ("3" * i) + "7")
        if N % prime == 0:
            q = prime
            p = N / q
            return p, q


def pastctfprimes(N):
    log.debug('factor N: try past ctf primes')
    primes = [long(x) for x in open(os.path.dirname(__file__)+ '/pastctfprimes.txt', 'r').readlines(
    ) if not x.startswith('#') and not x.startswith('\n')]
    for prime in primes:
        if N % prime == 0:
            q = prime
            p = N / q
            return p, q


def boneh_durfee(N, e):
    log.debug('factor N: try Boneh and Durfee attack')
    # use boneh durfee method, should return a d value, else returns 0
    # only works if the sageworks() function returned True
    # many of these problems will be solved by the wiener attack module but perhaps some will fall through to here
    # TODO: get an example public key solvable by boneh_durfee but not wiener
    sageresult = int(subprocess.check_output(
        ['sage', os.path.dirname(__file__)+ '/boneh_durfee.sage', str(N), str(e)]))
    if sageresult > 0:
        # use PyCrypto _slowmath rsa_construct to resolve p and q from d
        from Crypto.PublicKey import _slowmath
        tmp_priv = _slowmath.rsa_construct(
            long(N), long(e), d=long(sageresult))
        p = tmp_priv.p
        q = tmp_priv.q
        # d = sageresult
        return p, q


def smallfraction(N):
    log.debug('factor N: try Small fractions method when p/q is close to a small fraction')
    # Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
    # only works if the sageworks() function returned True
    sageresult = int(subprocess.check_output(
        ['sage', os.path.dirname(__file__)+ '/smallfraction.sage', str(N)]))
    if sageresult > 0:
        p = sageresult
        q = N / p
        return p, q


# 密文与模数不互素
def comfact_cn(N, c):
    log.debug('factor N: try Common factor between ciphertext and modulus attack')
    # Try an attack where the public key has a common factor with the ciphertext - sourcekris
    if c:
        commonfactor = libnum.gcd(N, c)
        if commonfactor > 1:
            q = commonfactor
            p = N / q
            return p, q


def smallq(N):
    log.debug('factor N: try small q')
    # Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
    for prime in libnum.primes(100000):
        if N % prime == 0:
            q = prime
            p = N / q
            return p, q


def isqrt(n):
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def fermat(n):
    log.debug("factor N: try Fermat's factorisation for close p and q")
    a = isqrt(n)
    b2 = a * a - n
    b = isqrt(n)
    count = 0
    while b * b != b2:
        a = a + 1
        b2 = a * a - n
        b = isqrt(b2)
        count += 1
    p = a + b
    q = a - b
    assert n == p * q
    return p, q


def p_q_2_close(N, fermat_timeout=10):
    # Try an attack where the primes are too close together from BKPCTF2016 - sourcekris
    # this attack module can be optional
    try:
        with timeout(seconds=fermat_timeout):
            return fermat(N)
    except FactorizationError:
        return


def rational_to_contfrac(x, y):
    '''
    Converts a rational x/y fraction into
    a list of partial quotients [a0, ..., an]
    '''
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients


def convergents_from_contfrac(frac):
    '''
    computes the list of convergents
    using the list of partial quotients
    '''
    convs = []
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs


def contfrac_to_rational(frac):
    '''Converts a finite continued fraction [a0, ..., an]
     to an x/y rational.
     '''
    if len(frac) == 0:
        return (0, 1)
    num = frac[-1]
    denom = 1
    for _ in range(-2, -len(frac) - 1, -1):
        num, denom = frac[_] * num + denom, num
    return (num, denom)


def bitlength(x):
    '''
    Calculates the bitlength of x
    '''
    assert x >= 0
    n = 0
    while x > 0:
        n = n + 1
        x = x >> 1
    return n


def is_perfect_square(n):
    '''
    If n is a perfect square it returns sqrt(n),

    otherwise returns -1
    '''
    h = n & 0xF  # last hexadecimal "digit"

    if h > 9:
        return -1  # return immediately in 6 cases out of 16.

    # Take advantage of Boolean short-circuit evaluation
    if (h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8):
        # take square root if you must
        t = isqrt(n)
        if t * t == n:
            return t
        else:
            return -1

    return -1


def wiener_attack(n, e):
    log.debug("factor N: try Wiener's attack")
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)

    for (k, d) in convergents:

        # check if d is actually the key
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s * s - 4 * n
            if(discr >= 0):
                t = is_perfect_square(discr)
                if t != -1 and (s + t) % 2 == 0:
                    return nde_2_pq(n, d, e)


def nde_2_pq(n, d, e):
    tmp_priv = _slowmath.rsa_construct(long(n), long(e), d=long(d))
    p = tmp_priv.p
    q = tmp_priv.q
    return p, q
