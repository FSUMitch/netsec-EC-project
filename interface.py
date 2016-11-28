#!/usr/bin/python

#Mitch Schmidt && Brandon Everhart
#Elliptic Curve Crypto Project

#commandline interface 

import sys
import argparse 
import ECproj

ec = ECproj.EC()

parser = argparse.ArgumentParser()

#generate users private and public keys
parser.add_argument("-gk", "--generateKeys", help="Generate a key pair.", action="store_true")

#create two users shared secret
parser.add_argument("-gs", "--generateSecret", action="store_true")
parser.add_argument("-sk", "--secretkey")
parser.add_argument("-pk", "--publickey")

#specify the output file
parser.add_argument("-o", "--outputFile", help="Designate output file: -o \"FileName\"")

#encrypt a file with a given sharedSecret
parser.add_argument("-e", "--encryptMsg")

#decrypt a file with a given sharedSecret
parser.add_argument("-d", "--decryptMsg")

#shared secret to encrypt and decrypt with
parser.add_argument("-ss", "--sharedSecret")

#sign a msg
parser.add_argument("-s", "--sign")

#verify a msg signature
parser.add_argument("-v","--verify")

#specify message when verifying signature
parser.add_argument("-m", "--message")

#parse command line arguments
args = parser.parse_args()


#generating a public and private key for a user: -gk -o [outputfile]
if args.generateKeys:

	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when generating keys." )
		sys.exit()

	file = open(args.outputFile,'w')
	secret, public = ec.genkeys()
	file.write(str(secret)+"\n")
	file.write(str(public))


#generate shared secret: -gs -sk [secretkey] -pk [publickey] -o [outputfile]	
if args.generateSecret:

	if (args.secretkey is None) or (args.publickey is None):
		print("Error: must provide your secret key and the senders public key when creating shared secret." )
		sys.exit()
	
	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when creating shared secret." )
		sys.exit()
	
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
	

#sign a message: -s [message] -sk [secretkey]
if args.sign is not None:

	if args.secretkey is None:
		print("Error: must provide secret key when signing.")
		sys.exit()

	if args.outputFile is None:
		print("Error: must provide output file with the \"-o\" flag when signing a message." )
		sys.exit()

	message = open(args.sign, 'r').read()
	byteMsg = int(message,2).to_bytes((len(message)+7) // 8, byteorder='big')
	key = int(open(args.secretkey, 'r').readline())
	open(args.outputFile,'w').write(str(ECproj.sign(byteMsg, ec, key)))


#verify a signature: -v [signature] -pk [publickey] -m [message]
if args.verify is not None:
	
	if args.publickey is None:
		print("Error: must provide public key when verifying a signature.")
		sys.exit()

	message = open(args.message, 'r').read()
	byteMsg = int(message,2).to_bytes((len(message)+7) // 8, byteorder='big')
	
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

	print(ECproj.verify(byteMsg, ec, point, signature))
