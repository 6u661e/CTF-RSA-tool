from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes
from data import flag, hint
from sympy import nextprime
from gmpy2 import iroot, invert



m = bytes_to_long(bytes(flag, encoding='utf-8'))

p = getPrime(1024)

q = nextprime(p)
r = nextprime(q)
n = p*q
phi = (p-1)*(q-1)

e = 0x10001

d = invert(e, phi)
c = pow(m, e, n)
dp = d % (p-1)
dq = d % (q-1)
print("c=", c)
print("dp=", dp)
print("dq=", dq)


# ------------------------------------------------------


P_ = nextprime(phi)
Q_ = getPrime(512)


N_ = P_*Q_
PHI_ = (P_-1)*(Q_-1)
M_ = bytes_to_long(bytes(hint, encoding='utf-8'))

E_ = 0x10001
D_ = invert(E_, PHI_)
C_ = pow(M_, E_, N_)

print("C_=", C_)
print("N_=", N_)
print("PHI_=", PHI_)

