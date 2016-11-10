#!/usr/bin/python

#Mitch Schmidt
#Elliptic Curve Crypto Project

#y ** 2 = x ** 3 - 3*x + b mod p

import os, gmpy
from copy import copy as copy
from fractions import Fraction

NBITS = 256
#constants for nist Curve P-256 "domain constants"
PRIME = 115792089210356248762697446949407573530086143415290314195533631308867097853951
ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369
ACOEF = -3
BCOEF = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
XBASE = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
YBASE = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

class EC:
	def __init__(self, nbits=NBITS, prime=PRIME, order=ORDER, acoef=ACOEF, bcoef=BCOEF, xbase=XBASE, ybase=YBASE):
		self.nbits = nbits
		self.prime = prime
		self.order = order
		self.acoef = acoef
		self.bcoef = bcoef
		self.xbase = xbase
		self.ybase = ybase

		if self.prime % 8 == 1:
			raise ValueError("Prime cannot be congruent to 1 mod 8.")

	def genkeys(self):
		private = int(str(os.urandom(self.nbits)).encode('hex'), 16)
		
		public = ""
		return private, public		

class ECpoint:
	ec = EC()

	#we call the point at infinity (0,0) because this invalid point in an EC
	def __init__(self, x=0, y=0, ec=EC()):
		self.x = x
		self.y = y
		self.ec = ec

		assert not type(x) == type(int)
		assert not type(y) == type(int)
		
	def isvalid(self):
		if self.x == self.y == 0:#true if pai
			return True

		res = pow(self.x, 3, self.ec.prime) + self.ec.acoef * self.x + self.ec.bcoef - pow(self.y, 2, self.ec.prime)
		
		return not (res % 23)

	def getPointFromX(self, x):
		#plug into equation
		ysq = x ** 3 - a * x + self.ec.bcoef

		#now need to find square root mod prime
		#used http://www.mersennewiki.org/index.php/Modular_Square_Root
		if self.ec.prime == 2:
			res = ysq % 2
		elif self.ec.prime == 3 % 8:
			res = pow(ysq, int((self.ec.prime + 1) / 4), self.ec.prime)
		elif self.ec.prime == 5 % 8:
			v = pow(2*ysq, int((self.ec.prime - 5) / 8), self.ec.prime)
			i = 2 * a * v ** 2 % self.ec.prime
			res = a * v * (i - 1) % self.ec.prime
		else:
			res = "not implemented"
			raise ValueError("not implemented")
			
		return (ECpoint(x,res), ECpoint(x,-1*res%self.ec.prime))

	def __add__(self, q):
		assert type(q) == type(ECpoint())
		
		if not self.x == self.y == 0 and not q.x == q.y == 0:
			if self.x == q.x and self.y == q.y:
				#double
				slope = (3 * self.x ** 2 + self.ec.acoef) * gmpy.invert(2 * self.y, self.ec.prime) % self.ec.prime

			elif self.y == -1*q.y:
				#negate
				res = copy.copy(self)
				return res

			else:
				#regular add
				slope = (self.y-q.y) * gmpy.invert(self.x-q.x, self.ec.prime) % self.ec.prime

			x = (slope ** 2 - self.x - q.x) % self.ec.prime
			y = (-slope * x + slope * self.x - self.y) % self.ec.prime
			
			resEC = copy(self)
			resEC.x, resEC.y = x, y
			return -resEC

		elif self.x == 0:#if self is pai
			return q
			
		else:
			return copy(self)

	def __str__(self):
		return ("(" + str(self.x) + ", " + str(self.y) + ")")

	def __mul__(self, scalar):
		#double and add algo
		#remember scalars are additive when adding ecp's
		if scalar < 0:
			neg = True
			scalar *= -1
		else:
			neg = False

		res = ECpoint(0, 0, self.ec)
		if scalar == 0:
			return res

		if scalar == 1:
			return copy(self)
	
		temp = copy(self)

		return reduce(lambda x, y: y + x, [r*int(i, 2) for (i, r) in zip(str(bin(scalar))[:1:-1], self.multgen())])

	def multgen(self):
		temp = copy(self)
		yield temp
		
		while True:
			temp = temp + temp
			yield temp

	def __neg__(self):
		res = copy(self)
		res.y = -self.y % self.ec.prime

		return res

print ("E : y ** 2 = x ** 3 + a * x + b (mod p)")

ec = EC(5, 23, None, 1, 0, 9, 5)
ecp = ECpoint(9, 5, ec)
pai = ECpoint(0, 0)

print '-----'
#sanity checks
a = (ecp + ecp + ecp + ecp + ecp)
print a, a.isvalid()
print '---'
b = (ecp * 5)
print b, b.isvalid()

print ("Randomly generated keys:" + str(ec.genkeys()))
