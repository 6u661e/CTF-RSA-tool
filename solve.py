#!/usr/local/bin/python
# coding:utf-8
import argparse
from Crypto.PublicKey import RSA
import subprocess
import lib.RSAutils
import libnum

split_char_dic = ['=', ':', 'is']


# Check if sage is installed and working
def sageworks():
    try:
        sageversion = subprocess.check_output(['sage', '-v'])
    except OSError:
        return False

    if 'SageMath version' in sageversion:

        return True
    else:
        return False


def input_file(path):
    multiple = False
    with open(path) as dfile:
        data = {}
        data_lines = dfile.readlines()
        for i in split_char_dic:
            if i in data_lines[0]:
                split_char = i
                break
        for k in data_lines:
            if not k.strip():
                continue
            key = k.split(split_char)[0].strip().lower()
            value = k.split(split_char)[1].strip()
            value = long(int(value, 16)) if '0x' in value else long(int(value))
            if key in data and value != data[key]:
                if isinstance(data[key], list):
                    data[key].append(value)
                else:
                    data[key] = [data[key], value]
                multiple = True
            else:
                data[key] = value
    return data, multiple


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='It helps CTFer to get first blood of RSA-base CTF problems')

    # group1用于指定是否需要打印私钥及待解密的密文或者自动识别的文本
    group1 = parser.add_mutually_exclusive_group(required=True)
    # 密文可以指定密文文件，也可以指定它对应的十进制值
    group1.add_argument(
        '--decrypt', help='decrypt a file, usually like "flag.enc"', default=None)
    group1.add_argument(
        '-c', '--decrypt_int', type=long, help='decrypt a long int num', default=None)
    group1.add_argument(
        '--private', help='Print private key if recovered', action='store_true')
    group1.add_argument(
        '-i', '--input', help='input a file with all necessary parameters (see examples/input_example.txt)')
    group1.add_argument(
        '-g', '--gadget', help='Use some gadgets to pre-process your data first', action='store_true')

    group2 = parser.add_argument_group(
        title='some gadgets', description='Pre-process your data (with --gadget together)')
    group2.add_argument(
        '--createpub', help='Take N and e and output to file specified by "-o" or just print it', action='store_true')
    group2.add_argument(
        '-o', "--output", help='Specify the output file path in --createpub mode.')
    group2.add_argument(
        '--dumpkey', help='Just print the RSA variables from a key - n,e,d,p,q', action='store_true')
    group2.add_argument(
        '--enc2dec', help='get cipher (in decimalism) from a encrypted file')

    # group3用于指定一个密钥pem文件 ，或指定需要的模数值
    group3 = parser.add_argument_group(
        title='the RSA variables', description='Specify the variables whatever you got')
    group3.add_argument(
        '-k', '--key', help='pem file, usually like ".pub" or ".pem", and it begins with "-----BEGIN"')
    group3.add_argument('-N', type=long, help='the modulus')
    group3.add_argument('-e', type=long, help='the public exponent')
    group3.add_argument('-d', type=long, help='the private exponent')
    group3.add_argument('-p', type=long, help='one factor of modulus')
    group3.add_argument('-q', type=long, help='one factor of modulus')

    # group4用于指定一特殊方法中所需要的额外参数
    group4 = parser.add_argument_group(
        title='extra variables', description='Used in some special methods')
    group4.add_argument('--KHBFA', type=long,
                        help='use Known High Bits Factor Attack, this specify the High Bits of factor', default=None)
    group4.add_argument('--pbits', type=long,
                        help='customize the bits lenth of factor, default is half of n`s bits lenth', default=None)

    parser.add_argument(
        '-v', '--verbose', help='print details', action='store_true')
    args = parser.parse_args()

    # if createpub mode generate public key then quit
    if args.createpub:
        if args.N is None or args.e is None:
            raise Exception(
                "Specify both a modulus and exponent on the command line. See --help for info.")
        if args.output:
            with open(args.output, 'w') as file:
                file.write(RSA.construct(
                    (args.N, args.e)).publickey().exportKey())
            print 'saved in %s' % args.output
        else:
            print RSA.construct((args.N, args.e)).publickey().exportKey()
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

    # if enc2dec mode print cipher in dec then quit
    if args.enc2dec:
        enc_data = open(args.enc2dec, 'r').read()
        print "[*] c : " + str(libnum.s2n(enc_data))
        quit()

    if sageworks():
        args.sageworks = True
    else:
        args.sageworks = False
    if args.input:
        args.data, args.multiple = input_file(args.input)
    else:
        args.data, args.multiple = None, False
    attackobj = lib.RSAutils.RSAAttack(args)
    attackobj.attack()
