#!/bin/python

import base64
import os

# prepare a file of ct:pt for DES brute force with Hashcat

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
    ctFmat.write(l.strip() + ':' + pt.readline())

tmp.close()
os.remove('tmp.txt')
ctFmat.close()
ct.close()
pt.close()
