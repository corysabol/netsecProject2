#!/bin/python

import base64
import binascii
import os

# Author Cory Sabol
# prepare a file of ct:pt for DES brute force with Hashcat
# the format of the resulting dictionary file is:
# <hexadecimal ciphertext>:<hexadecimal plaintext>

ct = open('b64_DES_10000CipherWords.txt', 'r')
pt = open('10000words.txt', 'r')
ctFmat = open('dictionary.txt', 'w') #use files to save memory 
tmp = open('tmp.txt', 'w')

b = None
while b != "":
    b = ct.read(1) #read a byte at a time
    if b == ",":
        tmp.write('\n') #replace , with \n
    else:
        tmp.write(b) #preserve all non , characters

tmp.close()
tmp = open('tmp.txt', 'r')

for l in tmp:
    ctFmat.write(binascii.hexlify(base64.b64decode(l.strip()))+ ':' + binascii.hexlify(pt.readline().strip()) + '\n')

tmp.close()
os.remove('tmp.txt')
ctFmat.close()
ct.close()
pt.close()
