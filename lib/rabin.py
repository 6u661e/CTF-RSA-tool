# coding=utf-8
import libnum
import factor_N


def solve(N, c, p=None, q=None):
    if not p and not q:
        factor = factor_N.solve(N)
        if factor and len(factor) is 2:
            p = factor[0]
            q = factor[1]
        else:
            print '----------rabin attck fail----------'
            print 'please offer p and q'
            print '------------------------------------'
            return
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
        print s.decode('hex')


if __name__ == '__main__':
    p = 275127860351348928173285174381581152299
    q = 319576316814478949870590164193048041239
    N = p * q
    e = 2
    m = 'this is a test'
    c = pow(libnum.s2n(m), e, N)
    solve(N, c)
    solve(N, c, p=p, q=q)
