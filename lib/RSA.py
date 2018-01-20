import nde2pq


'''
分析参数，选择攻击方法，放回结果
'''


class RSA:
    def __init__(self, p=None, q=None, n=None, d=None, e=None):
        self.p = p
        self.q = q
        self.n = n
        self.d = d
        self.e = e

    def solve_nde2pq(self, n, d, e):
        return nde2pq.solve(n, d, e)
