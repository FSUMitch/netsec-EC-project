#!/usr/bin/python

#Mitch Schmidt && Brandon Everhart
#Elliptic Curve Crypto Project

#-----ENCRYPTION-----
#First, initialize with an EC
#Second, generate a shared key (using a published public key of the recipient and ephemeral public key)
#Third, use shared key's x val as a symmetric key and use that to encrypt the message with AES
#Fourth, xor shared key and symmetric key = sentkey
#Fifth, compute signature
#Sixth, send (ephemeral public key, message, and signature)

#-----DECRYPTION-----
#First, recover shared key = their public key * your private key
#Decrypt message using shared key.x

#y ** 2 = x ** 3 - 3*x + b mod p
#from __future__ import print_function

import gmpy2, math
from copy import copy
from random import SystemRandom
from Crypto.Cipher import AES#not trying to implement AES, just using is as the symmetric algo after ECDH
from Crypto import Random
from functools import reduce
from binascii import *
from hashlib import sha256
import OAEP

DEMO = False


BLOCKBITS = 256
#constants for nist Curve P-256 "domain constants"
NBITS = 256
PRIME = 115792089210356248762697446949407573530086143415290314195533631308867097853951
ORDER = 115792089210356248762697446949407573529996955224135760342422259061068512044369
ACOEF = -3
BCOEF = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
XBASE = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
YBASE = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

#constants for secp256k1 "domain constants"
NBITS = 256
PRIME = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
ACOEF = 0
BCOEF = 7
XBASE = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
YBASE = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

#not sure if we actually need this but w/e
CHARLENGTH = 8
 
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
		#generates random keypair
		private = SystemRandom().randrange(1,self.order)
		self.basep = ECpoint(self.xbase, self.ybase, self) 
		
		public = self.basep * private
		return private, public

	def gensharedsecret(self, mysecret, yourpublic):
		#returns x value of shared secret, which is what we will use to encrypt
		return (yourpublic * mysecret).x

class ECpoint:
	ec = EC()

	#we call the point at infinity (0,0) because this invalid point in an EC
	def __init__(self, x=0, y=0, ec=EC()):
		self.x = x
		self.y = y
		self.ec = ec

		assert not type(x) == type(int)
		assert not type(y) == type(int)
		
	def isvalid(self):#helper function
		#returns true if point is on ec, false if not
		if self.x == self.y == 0:#true if pai
			return True

		res = pow(self.x, 3, self.ec.prime) + self.ec.acoef * self.x + self.ec.bcoef - pow(self.y, 2, self.ec.prime)
		
		return not (res % 23)

	def getPointFromX(self, x):
		#returns two points that x generates
		
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
		#add two points on an EC
		assert type(q) == type(ECpoint())
		
		if not self.x == self.y == 0 and not q.x == q.y == 0:
			if self.x == q.x and self.y == q.y:
				#double
				slope = (3 * self.x ** 2 + self.ec.acoef) * gmpy2.invert(2 * self.y, self.ec.prime) % self.ec.prime

			elif self.x == q.x and self.y != q.y:
				#negate
				res = copy.copy(self)
				res.x = 0
				res.y = 0
				return res

			else:
				#regular add
				slope = (self.y-q.y) * gmpy2.invert(self.x-q.x, self.ec.prime) % self.ec.prime

			x = (slope ** 2 - self.x - q.x) % self.ec.prime
			y = -(slope * (x - self.x) + self.y) % self.ec.prime
			
			resEC = copy(self)
			resEC.x, resEC.y = x, (y)
			return resEC

		elif self.x == 0:#if self is pai
			return q
			
		else:
			return copy(self)

	def __str__(self):
		#this is used to print (ECpoint)
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
		#generator to help with multiplication
		temp = copy(self)
		yield temp
		
		while True:
			temp = temp + temp
			yield temp

	def __neg__(self):
		#unary negative operator(used for addition)
		res = copy(self)
		res.y = -self.y % self.ec.prime

		return res

def Pad(message):
	#filler padding for later
	return message

def encrypt(msg):
	#encrypt message by computing key, generating random iv, then calling AES cipher
	key = bin(ec.gensharedsecret(salice, pbob))[2:]
	if DEMO:
		print (key, type(key))

	while len(key) % BLOCKBITS:
		key = key[:2] + '0' + key[2:]

	key = "".join([chr(int(key[i*CHARLENGTH:i*CHARLENGTH+CHARLENGTH],2)) for i in range(int(BLOCKBITS / CHARLENGTH))])
	key = str(key).encode('utf8')
	
	key = sha256(key).digest()
	
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CFB, iv)

	#magic
	padded =OAEP.pad(msg)
	if DEMO:
		print ("padded string: ", padded, type(padded))
	msg = iv + cipher.encrypt(padded)

	if DEMO:
		print("Encypted message:", msg)
	return (msg)

def decrypt(c):
	#decrypt message by computing key, generating random iv, then calling AES cipher	
	key = bin(ec.gensharedsecret(sbob, palice))[2:]

	while len(key) % BLOCKBITS:
		key = key[:2] + '0' + key[2:]

	key = "".join([chr(int(key[i*CHARLENGTH:i*CHARLENGTH+CHARLENGTH],2)) for i in range(int(BLOCKBITS / CHARLENGTH))])
	key = key.encode('utf8')
	
	key = sha256(key).digest()
	
	iv = c[:AES.block_size]
	cipher = AES.new(key, AES.MODE_CFB, iv)
	val = str(cipher.decrypt(c[AES.block_size:]))[2:-1]
	
	if DEMO:
		print ("val: ", val)
	val = OAEP.unpad(val)
	
	return val

def truncatehash(msg, order):
	#helper function returns the int value of message truncated to length of the order
	n = order
	
	#length of order
	bitlength = len(str(bin(n)))-2#length of order
	msghash =  sha256(msg).digest()#hash message

	if DEMO:
		print ("Bitlength =", bitlength)
		print ("msghash =", msghash)

	return int(str(bin(int.from_bytes(msghash, 'little')))[2:bitlength+2], 2)#take message, convert to int, then binary, then string and truncate and return

def sign(msg, curve, secret):
	"""
	1. Take a random int k < n - 1
	2. calculate P = kG (base point)
	3. calculate r = x % n
	4. calculate s = k^-1(z+rd) % n , if s or r = 0start over
	5. (r, s) is the signature
	"""

	#1
	n = int(curve.order)
	k = SystemRandom().randrange(1,n)
	if DEMO:
		print ("Random int:", k)
	
	#2
	basepoint = ECpoint(curve.xbase, curve.ybase)
	P = basepoint * k
	if DEMO:
		print ("Base point x:", basepoint.x)
		print ("Generated point:", P)
	 
	#3
	r  = int(P.x) % n
	if DEMO:
		print ("r =", r)
	
	#4
	kinverse = int(gmpy2.invert(k, n))
	z = truncatehash(msg, n)
	
	if DEMO:
		print ("n =", n)
		print ("truncated hash =", z)
	
	s = (kinverse * (z + r * secret)) % n
	sinverse = int(gmpy2.invert(s, n))
	if DEMO:
		print ("s =", s)
		print ("sinv =", sinverse)
		print ("left:", (sinverse*z)%n)
		print ("right:", (sinverse*r*secret)%n)
		
	if r * s == 0:
		return sign(msg, curve, secret)
		
	return (r, s)

def verify(msg, curve, public, sig):
	"""
	1. Calculate u = s^-1 z mode n
	2. Calculate v = s^-1 r mode n
	3. Calculate P = uG + vH (G = basepoint, H = public key)
	"""
	n = int(curve.order)
	sinverse = int(gmpy2.invert(sig[1], n))
	
	#1
	z = truncatehash(msg, n)
	u = (sinverse * z) % n
	
	#2
	r = sig[0]
	v = (sinverse * r) % n
	
	basepoint = ECpoint(curve.xbase, curve.ybase)
	if DEMO:
		print ("Base point:", basepoint)
		print ("sinv:", sinverse)
		print ("u:", u)
		print ("v:", v)

	P = basepoint * u + public * v

	if DEMO:
		print ("\nP.x:", P.x)
		print ("r:", sig[0])

	return (P.x == sig[0])

if __name__ == "__main__":
	print ("E : y ** 2 = x ** 3 + a * x + b (mod p)")
	ec = EC()

	#example to show how this stuff works
	salice, palice = ec.genkeys()
	sbob, pbob = ec.genkeys()

	print ("Randomly generated public key for alice:" + str(palice))
	print ("Randomly generated public key for bob:" + str(pbob))
	print ("Randomly generated private key for alice:" + str(salice))
	print ("Randomly generated private key for bob:" + str(sbob))

	print ("Shared secret1:", ec.gensharedsecret(salice, pbob))
	print ("Shared secret2:", ec.gensharedsecret(sbob, palice))

	message = "Attack at dawn"

	print ("padded message: ", OAEP.pad(message))
	
	#example encrypting/decrypting message
	encrypted = encrypt(message)
	output = decrypt(encrypted)
	print ("Decrypted message:", output)

	signature = sign(encrypted, ec, salice)
	print ("Signature of the message is: ", signature)
	
	verified = verify(encrypted, ec, palice, signature)
	print (verified)
