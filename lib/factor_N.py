# coding:utf-8
import requests
from bs4 import BeautifulSoup


def solve(N):
    res = requests.get('http://factordb.com/index.php?query=' + str(N))
    soup = BeautifulSoup(res.text, 'lxml')
    factor = []
    for i in soup.find_all('font'):
        if i.string and '.' not in str(i.string) and '*' not in str(i.string):
            factor.append(int(i.string))
    while N in factor:
        factor.remove(N)
    if factor:
        return factor
    else:
        print '----------factor N fail----------'
        print 'can not factor N or it is a prime number:' + str(N)
        print 'you may try tool "yafu" or other attck method'
        print '---------------------------------'
        return


if __name__ == '__main__':
    print solve(23)
    print solve(21)
    print solve(2718347230958302063664307796822677955117068459021260657354922005689260848289044963017156228357086136189547148251110860962129700380152097588614077466301)
    print solve(2887613214344884919351929779271966424579911172072088070184963726)
    print solve(87924348264132406875276140514499937145050893665602592992418171647042491658461)
