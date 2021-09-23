import os
import sys
from getopt import getopt
from random import randint

# set the number of charactors as a group
NUMBER_OF_GROUP = 4
# set the power of prime
MAX_NUMBER_DIGITS = 128
# Miller Rabin test SPRP base => can check prime larger than 2^64 at least
# copyright is https://miller-rabin.appspot.com/
BASE_CHECK = [2, 325, 9375, 28178, 450775, 9780504, 1795265022]

class _RSA:
    # initialize
    def __init__(self):
        # if prime has been generated already
        if os.path.exists('./rsa_key') & os.path.isfile('./rsa_key'):
            with open('./rsa_key', 'r') as f:
                self.__E = int(f.readline(), 16)
                self.__D = int(f.readline(), 16)
                self.__N = int(f.readline(), 16)
                return

        P, Q = _RSA.__prime_gen()
        R = (P - 1) * (Q - 1)
        self.__N = P * Q
        self.__D = 2 ** 64 + 1
        self.__E = R - 1
        
        for i in range(R, 1, -1):
            if(_RSA.__gcd(i, R) == 1):
                self.__E = i
                self.__D = _RSA.__ex_gcd(i, R)
                if(self.__E != self.__D): break

        with open('rsa_key', 'w') as f:
            f.write(hex(self.__E)[2:] + '\n')
            f.write(hex(self.__D)[2:] + '\n')
            f.write(hex(self.__N)[2:] + '\n')
    # generate odds which is 2^63 ~ 2^64-1
    def __binary_gen(digits):
        result = 1
        for _ in range(digits - 2):
            result = result << 1
            result += randint(0, 1)
        result = (result << 1) + 1
        return result

    def __fast_power(a, n, mod):
        base = a
        result = 1
        while(n):
            if(n & 1): result = (result * base) % mod
            base = (base ** 2) % mod
            n >>= 1
        return result

    def __Miller_Rabin(prime):
        if(prime == 2): return True
        elif(prime < 2 or prime & 1 == 0): return False

        # find an odd such that N - 1 can be written 2^r * d
        two_cnt = 0
        d = prime - 1
        while(d & 1 == 0):
            two_cnt += 1
            d //= 2

        # every bases will check N
        for base in BASE_CHECK:
            temp = base % prime
            if(temp == 0 or temp == 1 or temp == prime - 1): continue

            temp = _RSA.__fast_power(temp, d, prime)
            if(temp == 1 or temp == prime - 1): continue

            for _ in range(two_cnt - 1):
                temp = (temp * temp) % prime
                if(temp == 1): return False
                elif(temp == prime - 1): break
            
            if(temp != prime - 1): return False

        return True

    def __prime_gen():
        while(True):
            P = _RSA.__binary_gen(MAX_NUMBER_DIGITS)
            if(_RSA.__Miller_Rabin(P)): break
        
        while(True):
            Q = _RSA.__binary_gen(MAX_NUMBER_DIGITS)
            if(_RSA.__Miller_Rabin(Q) and P != Q): break

        return P, Q     

    def __gcd(a, b):
        while(b):
            temp = a % b
            a = b
            b = temp
        return a

    def __ex_gcd(a, b):
        if _RSA.__gcd(a, b) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, b

        while(v3):
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        
        return u1 % b

    def encryption(self, text, file):
        with open(file, 'w') as f:
            for text_comb in text:
                result = _RSA.__fast_power(text_comb, self.__E, self.__N)
                f.write(hex(result)[2:] + '/')

    def decryption(self, text, file):
        with open(file, 'w') as f:
            for num in text:
                temp_str = ''
                result = _RSA.__fast_power(num, self.__D, self.__N)
                for _ in range(4):
                    chr_n = result & 0xFFFF
                    if(chr_n != 0):
                        temp_str = chr(chr_n) + temp_str
                    result >>= 16
                f.write(temp_str)
            

def main():
    # initialize rsa key
    rsa = _RSA()
    # get operation options
    opts, args = getopt(sys.argv[1:], 'i:d:o:')
    # default set the output file is output.txt
    try:
        file_name = [arg for opt, arg in opts if opt == '-o'][0]
    except:
        cnt = 1
        file_name = 'output.txt'
        while(os.path.exists(file_name)):
            file_name = f'output({cnt}).txt'
            cnt += 1

    for opt, arg in opts:
        # excryption
        if opt == '-i':
            if(os.path.isfile(arg)):
                try:
                    num_list = []
                    with open(arg, 'r') as f:
                        while(True):
                            uni_num = 0 # compute the combination of text group
                            word = f.read(NUMBER_OF_GROUP)
                            if(len(word) == 0): break
                            for c in word:
                                uni_num <<= (4 * NUMBER_OF_GROUP)
                                uni_num += ord(c)
                            num_list.append(uni_num)
                    rsa.encryption(num_list, file_name)
                except:
                    # file open error
                    print('the argument is not correct')
                    return
            else:
                str_index = 0
                num_list = []
                while str_index < len(arg):
                    uni_num = 0
                    for c in arg[str_index : str_index + NUMBER_OF_GROUP]:
                        uni_num <<= (4 * NUMBER_OF_GROUP)
                        uni_num += ord(c)
                    str_index += NUMBER_OF_GROUP
                    num_list.append(uni_num)
                rsa.encryption(arg)
        # decryption
        elif opt == '-d':
            if(os.path.isfile('./' + arg)):
                try:
                    num_list = []
                    with open(arg, 'r') as f:
                        # string split and filter empty string
                        hex_list = list(filter(None, f.read().split('/')))
                        for hex_str in hex_list:
                            num_list.append(int(hex_str, 16))
                    rsa.decryption(num_list, file_name)
                except:
                    # file open error
                    print('the argument is not correct')
                    return
            else:
                num_list = []
                hex_list = list(filter(None, arg.split('/')))
                for hex_str in hex_list:
                    num_list.append(int(hex_str, 16))
                rsa.decryption(num_list, file_name)

if __name__ == "__main__":
    main()