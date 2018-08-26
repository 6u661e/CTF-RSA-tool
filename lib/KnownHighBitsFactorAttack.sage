import sys

n = Integer(sys.argv[1])
p4 = Integer(sys.argv[2])
pbits = Integer(sys.argv[3]) if len(sys.argv) > 3 else 2^(ceil(log_b(log_b(n,2),2))-1)
kbits = pbits - p4.nbits()
p4 = p4 << kbits
PR.<x> = PolynomialRing(Zmod(n))
f = x + p4
x0 = f.small_roots(X=2^kbits, beta=0.4)[0]
p = p4+x0
print int(p)