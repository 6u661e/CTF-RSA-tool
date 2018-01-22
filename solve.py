# coding:utf-8
import argparse
from Crypto.PublicKey import RSA
import subprocess
import lib.RSAutils


def sageworks():
    # Check if sage is installed and working
    try:
        sageversion = subprocess.check_output(['sage', '-v'])
    except OSError:
        return False

    if 'SageMath version' in sageversion:

        return True
    else:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='It helps CTFer to get flag quickly')
    parser.add_argument(
        '--private', help='Display private key if recovered', action='store_true')
    parser.add_argument(
        '--createpub', help='Take n and e and output to file specified by "-o" or just print it', action='store_true')
    parser.add_argument(
        '--dumpkey', help='Just dump the RSA variables from a key - n,e,d,p,q', action='store_true')

    # group1用于指定待解密的密文
    group1 = parser.add_mutually_exclusive_group()
    group1.add_argument(
        '--decrypt', help='decrypt a file, for example flag.enc', default=None)
    group1.add_argument(
        '-c', '--decrypt_int', type=long, help='decrypt a long int num, such as c and cipher', default=None)
    # group2用于指定一个密钥pem文件 ，或指定需要的模数值
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument(
        '-k', '--key', help='pem file, which begins with "-----BEGIN"')
    group2.add_argument('-N', type=long)
    parser.add_argument('-e', type=long, help='the public exponent')
    parser.add_argument('-d', type=long, help='the private exponent')
    parser.add_argument('-p', type=long, help='factor of modulus')
    parser.add_argument('-q', type=long, help='factor of modulus')

    # 下面这些用于一些特殊的攻击方法中(共模攻击，模不互素，Basic Broadcast Attack，Known High Bits Message Attack，Factoring with High Bits Known)
    parser.add_argument('--HighBitsOfMessage', type=long,
                        help='used in Known High Bits Message Attack')
    parser.add_argument('--HighBitsOfFactor', type=long,
                        help='used in Factoring with High Bits Known')
    parser.add_argument('--n1', type=long, help='used in some special methods')
    parser.add_argument('--n2', type=long, help='used in some special methods')
    parser.add_argument('--n3', type=long, help='used in some special methods')
    parser.add_argument('--e1', type=long, help='used in some special methods')
    parser.add_argument('--e2', type=long, help='used in some special methods')
    parser.add_argument('--e3', type=long, help='used in some special methods')
    parser.add_argument('--c1', help='used in some special methods')
    parser.add_argument('--c2', help='used in some special methods')
    parser.add_argument('--c3', help='used in some special methods')

    # 一些可选参数
    parser.add_argument(
        '--verbose', help='verbose mode', action='store_true')
    parser.add_argument(
        '-o', "--output", help='Specify the output file in --createpub mode.')

    args = parser.parse_args()

    # if createpub mode generate public key then quit
    if args.createpub:
        if args.n is None or args.e is None:
            raise Exception(
                "Specify both a modulus and exponent on the command line. See --help for info.")
        if args.output:
            with open(args.output, 'w') as file:
                file.write(RSA.construct((args.n, args.e)).publickey().exportKey())
            print 'saved in %s' % args.output
        else:
            print RSA.construct((args.n, args.e)).publickey().exportKey()
        quit()

    # if dumpkey mode dump the key components then quit
    if args.dumpkey:
        if args.key is None:
            raise Exception(
                "Specify a key file to dump with --key. See --help for info.")

        key_data = open(args.key, 'rb').read()
        key = RSA.importKey(key_data)
        print "[*] n: " + str(key.n)
        print "[*] e: " + str(key.e)
        if key.has_private():
            print "[*] d: " + str(key.d)
            print "[*] p: " + str(key.p)
            print "[*] q: " + str(key.q)
        quit()

    if sageworks():
        args.sageworks = True
    else:
        args.sageworks = False
    attackobj = lib.RSAutils.RSAAttack(args)
    attackobj.attack()
