#!/usr/bin/python

#Mitch Schmidt && Brandon Everhart
#Elliptic Curve Crypto Project

#commandline interface 

import sys
import argparse 
import ECproj

ec = ECproj.EC()

#constants for P-192 curve
NBITS192 = 192		
PRIME192 = 6277101735386680763835789423207666416083908700390324961279
ORDER192 = 6277101735386680763835789423176059013767194773182842284081
ACOEF192 = -3
BCOEF192 = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
XBASE192 = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
YBASE192 = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811

#constants for P-256 curve
NBITS256 = 256
PRIME256 = 115792089210356248762697446949407573530086143415290314195533631308867097853951
ORDER256 = 115792089210356248762697446949407573529996955224135760342422259061068512044369
ACOEF256 = -3
BCOEF256 = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
XBASE256 = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
YBASE256 = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

#constants for P-384 curve
NBITS384 = 384
PRIME384 = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
ORDER384 = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
ACOEF384 = -3
BCOEF384 = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
XBASE384 = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
YBASE384 = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f

#constants for P-521 curve
NBITS521 = 521
PRIME521 = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
ORDER521 = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
ACOEF521 = -3
BCOEF521 = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
XBASE521 = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
YBASE521 = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650

parser = argparse.ArgumentParser()

#generate users private and public keys
parser.add_argument("-gk", "--generateKeys", help="generating a public and private key for a user: -gk (-ec [ellipticCurve])-o [outputfile]", action="store_true")

#create two users shared secret
parser.add_argument("-gs", "--generateSecret", help="generate shared secret: -gs -sk [secretkey] -pk [publickey] (-ec [ellipticCurve]) -o [outputfile]", action="store_true")
parser.add_argument("-sk", "--secretkey", help="File containing your secret key")
parser.add_argument("-pk", "--publickey", help="File containing the other parties public key")

#specify the output file
parser.add_argument("-o", "--outputFile", help="Designate output file: -o \"FileName\"")

#encrypt a file with a given sharedSecret
parser.add_argument("-e", "--encryptMsg", help="Encrypt a msg: -e [message] -ss [sharedsecret] -o [outputfile]")

#decrypt a file with a given sharedSecret
parser.add_argument("-d", "--decryptMsg", help="Decrypt a msg: -d [message] -ss [sharedsecret] (-o [outputFile])")

#shared secret to encrypt and decrypt with
parser.add_argument("-ss", "--sharedSecret", help="File containing shared secret: -ss 'FileName'")

#sign a msg
parser.add_argument("-s", "--sign", help="Sign a message: -s [ciphertext] -sk [secretkey] (-ec [ellipticCurve])")

#verify a msg signature
parser.add_argument("-v","--verify", help="Verify a signature: -v [signature] -pk [publickey] -c [cipherText] (-ec [ellipticCurve])")

#specify ciphertext when verifying signature
parser.add_argument("-c", "--cipherText", help="Specify ciphertext when verifying signature: -c [cipherText]")

#specify an elliptic curve to be used
parser.add_argument("-ec", "--ellipticCurve", choices=['P-192','P-256','P-384','P-521','secp256k1'], help="Specify an elliptic curve to be used: -ec [ellipticCurve]")

#parse command line arguments
args = parser.parse_args()


def curveChoice(option):
	#if (args.ellipticCurve is None) or (args.ellipticCurve == 'secp256k1'):
		#ec = ECproj.EC()
		#Do nothing

	if option == 'P-192':
		#ec = ECproj.EC(NBITS192,PRIME192,ORDER192,ACOEF192,BCOEF192,XBASE192,YBASE192)
		ec.nbits = NBITS192
		ec.prime = PRIME192
		ec.order = ORDER192
		ec.acoef = ACOEF192
		ec.bcoef = BCOEF192
		ec.xbase = XBASE192
		ec.ybase = YBASE192

	if option == 'P-256':
		#ec = ECproj.EC(NBITS256,PRIME256,ORDER256,ACOEF256,BCOEF256,XBASE256,YBASE256)
		ec.nbits = NBITS256
		ec.prime = PRIME256
		ec.order = ORDER256
		ec.acoef = ACOEF256
		ec.bcoef = BCOEF256
		ec.xbase = XBASE256
		ec.ybase = YBASE256

	if option == 'P-384':
		#ec = ECproj.EC(NBITS384,PRIME384,ORDER384,ACOEF384,BCOEF384,XBASE384,YBASE384)
		ec.nbits = NBITS384
		ec.prime = PRIME384
		ec.order = ORDER384
		ec.acoef = ACOEF384
		ec.bcoef = BCOEF384
		ec.xbase = XBASE384
		ec.ybase = YBASE384

	if option == 'P-521':
		#ec = ECproj.EC(NBITS521,PRIME521,ORDER521,ACOEF521,BCOEF521,XBASE521,YBASE521)
		ec.nbits = NBITS521
		ec.prime = PRIME521
		ec.order = ORDER521
		ec.acoef = ACOEF521
		ec.bcoef = BCOEF521
		ec.xbase = XBASE521
		ec.ybase = YBASE521	


#generating a public and private key for a user: -gk (-ec [ellipticCurve])-o [outputfile]
if args.generateKeys:

	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when generating keys." )
		sys.exit()

	curveChoice(args.ellipticCurve)

	file = open(args.outputFile,'w')
	secret, public = ec.genkeys()
	file.write(str(secret)+"\n")
	file.write(str(public))


#generate shared secret: -gs -sk [secretkey] -pk [publickey] (-ec [ellipticCurve]) -o [outputfile]	
if args.generateSecret:

	if (args.secretkey is None) or (args.publickey is None):
		print("Error: must provide your secret key and the senders public key when creating shared secret." )
		sys.exit()
	
	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when creating shared secret." )
		sys.exit()
	
	
	curveChoice(args.ellipticCurve)

	#secret key is on first line of file
	secret = int(open(args.secretkey, 'r').readline())
	
	#public key is on second line of file
	file = open(args.publickey, 'r')
	file.readline()
	public = file.readline()
	
	#get two ints from public key to make EC point
	tupXY = public.partition(",")
	x = int(tupXY[0][1:])
	y = int(tupXY[2][:-1])
	point = ECproj.ECpoint(x,y,ec)


	sharedSecret  = ec.gensharedsecret(secret,point)
	outputFile = open(args.outputFile,'w').write(str(sharedSecret))
	

#encrypt a msg: -e [message] -ss [sharedsecret] -o [outputfile]
if args.encryptMsg is not None:

	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when encrypting a message." )
		sys.exit()

	if args.sharedSecret is None:
		print("Error: must provide shared secret when encrypting.")
		sys.exit()

	message = open(args.encryptMsg, 'r').read()
	key = int(open(args.sharedSecret, 'r').read())
	open(args.outputFile, 'w').write(bin(int.from_bytes(ECproj.encrypt(message, key), byteorder='big'))[2:])
	

#decrypt a msg: -d [message] -ss [sharedsecret] (-o [outputFile])
if args.decryptMsg is not None:

	if args.sharedSecret is None:
		print("Error: must provide shared secret when decrypting.")
		sys.exit()

	message = open(args.decryptMsg, 'r').read()
	byteMsg = int(message,2).to_bytes((len(message)+7) // 8, byteorder='big')
	key = int(open(args.sharedSecret, 'r').read())
	result = ECproj.decrypt(byteMsg,key)

	if args.outputFile is None:
		print(result)
	else:	
		open(args.outputFile,'w').write(str(result))
	

#sign a message: -s [ciphertext] -sk [secretkey] (-ec [ellipticCurve])
if args.sign is not None:

	if args.secretkey is None:
		print("Error: must provide secret key when signing.")
		sys.exit()

	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when signing a message." )
		sys.exit()

	curveChoice(args.ellipticCurve)

	cipherText = open(args.sign, 'r').read()
	byteCT = int(cipherText,2).to_bytes((len(cipherText)+7) // 8, byteorder='big')
	key = int(open(args.secretkey, 'r').readline())
	open(args.outputFile,'w').write(str(ECproj.sign(byteCT, ec, key)))


#verify a signature: -v [signature] -pk [publickey] -c [cipherText] (-ec [ellipticCurve])
if args.verify is not None:
	
	if args.publickey is None:
		print("Error: must provide public key when verifying a signature.")
		sys.exit()

	curveChoice(args.ellipticCurve)

	cipherText = open(args.cipherText, 'r').read()
	byteCT = int(cipherText,2).to_bytes((len(cipherText)+7) // 8, byteorder='big')
	
	temp = open(args.verify, 'r').read()
	tupAB = temp.partition(",")
	a = int(tupAB[0][1:])
	b = int(tupAB[2][:-1])
	signature = (a,b)

	file = open(args.publickey, 'r')
	file.readline()
	public = file.readline()
	tupXY = public.partition(",")
	x = int(tupXY[0][1:])
	y = int(tupXY[2][:-1])
	point = ECproj.ECpoint(x,y,ec)

	print(ECproj.verify(byteCT, ec, point, signature))


