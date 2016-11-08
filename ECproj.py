#!/usr/bin/python

#Mitch Schmidt
#Elliptic Curve Crypto Project

#y ** 2 = x ** 3 - 3*x + b mod p

import os

#constants for nist Curve P-256 "domain constants"
nbits = 256
prime = 115792089210356248762697446949407573530086143415290314195533631308867097853951
order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
bcoef = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
xbase = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
ybase = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)


def calcvalid(x, y):
    res = pow(x, 3, prime) - 3 * x + bcoef - pow(y, 2, prime)
    print ("res:", res, "or", res % prime)
    
    return res % prime

def genkeys():
    private = int(str(os.urandom(nbits)).encode('hex'), 16)
    
    public = ""
    return private, public
    
print ("E : y ** 2 = x ** 3 - 3 * x + b (mod p)")

res = calcvalid(xbase, ybase)

print ("xbase:", xbase, "ybase:", ybase, "res:", res % prime)

print ("Randomly generated keys:", genkeys())
