#!/usr/bin/python

'''
Author: Brandon Everhart
Modified: Nov. 10th, 2016
Description: Optimal asymmetric encryption padding implementation
'''

import hashlib #sha-256
import binascii #Used for coverting between Ascii and binary
from random import SystemRandom #Generate secure random numbers


#constants
nBits = 512
k0BitsInt = 256
k0BitsFill = '0256b' 
errors='surrogatepass'
encoding='utf-8'

'''
Helper function to change a Character string into a binary string.
Making sure to have full byte output (Don't drop leading 0's)
Funct: CharsToBinary
Arguments: msg, a Charater string
		   errors, used when encoding the msg
return: bits, a binary string'''
def CharsToBinary(msg,errors):
	bits = bin(int.from_bytes(msg.encode(encoding,errors), 'big'))[2:]
	return bits.zfill(8 * ((len(bits) + 7) // 8))

'''
Helper function to change a binary string into a character string.
Funct: BinaryToChars
Arguments: msg, a Charater string
		   errors, used when decoding the bytes
return: n, a character string'''
def BinaryToChars(bits,errors):
	n = int(bits, 2)
	return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

def pad(msg):
	'''
	Create two oracles using sha-256 hash function.
	oracle1 is our first hash function used. Used to hash a random integer.
	oracle2 is the second hash function used. Used to hash the result of XOR(paddedMsg, hash(randBitStr))'''
	oracle1 = hashlib.sha256()
	oracle2 = hashlib.sha256()

	'''
	Generate a random integer that has a size of k0bits. Format the random int as a binary string making 
	sure to maintain leading zeros with the K0BitsFill argument.'''
	randBitStr = format(SystemRandom().getrandbits(k0BitsInt), k0BitsFill )
	
	'''
	Change our msg string to a binary string. '''
	binMsg = CharsToBinary(msg, errors)

	'''
	Get last block of msg'''
	msgLen = len(binMsg)
	if msgLen%256 == 0:
		numBlocks =  int( msgLen/256)-1
	else:
		numBlocks =  int( msgLen/256)		
	lastBlock = binMsg[(numBlocks*256):]
	
	'''
	If the input msg has a binary length shorter than (nBits-k0Bits) then append k1Bits 0's to the end of the msg.
	Where k1Bits is the number of bits to make len(binMsg) = (nBits-k0Bits).'''
	#if len(binMsg) <= (nBits-k0BitsInt):
	#	print ( "here")
	k1Bits = nBits - k0BitsInt - len(lastBlock) 
	zeroPaddedLastBlock = lastBlock + ('0'*k1Bits)
	

	'''
	Use the hashlib update method to pass the values we wish to be hashed to the oracle. Then use
	the hashlib hexdigest method to hash the value placed in the oracle by the update method, and
	return the hex repersentation of this hash. Change our hash output, zeroPaddedMsg, and
	randBitStr to integeres to use XOR operation. Format the resulting ints as binary strings.
	Hashing and XOR ordering follows OAEP algorithm.'''
	oracle1.update(randBitStr.encode(encoding))
	x = format(int(zeroPaddedLastBlock, 2) ^ int(oracle1.hexdigest(), 16), '0256b')
	oracle2.update(x.encode(encoding))
	y = format(int(oracle2.hexdigest(), 16) ^ int(randBitStr, 2), k0BitsFill)
	
	return binMsg[0:numBlocks*256]+x+y

def unpad(msg):
	'''
	Create two oracles using sha-256 hash function.
	oracle1 is our first hash function used. Used to hash a random integer.
	oracle2 is the second hash function used. Used to hash the result of XOR(paddedMsg, hash(randBitStr))'''
	oracle1 = hashlib.sha256()
	oracle2 = hashlib.sha256()

	'''
	Get last block'''
	msgLen = len(msg)
	numBlocks =  int( msgLen/256)-2
	lastBlock = msg[numBlocks*256:]
	
	x = lastBlock[0:256]
	y = lastBlock[256:]

	oracle2.update(x.encode(encoding))
	r = format(int(y,2) ^ int(oracle2.hexdigest(), 16), k0BitsFill)

	oracle1.update(r.encode(encoding))
	msgWith0s = format( int(x,2) ^ int(oracle1.hexdigest(), 16), '0256b')

	originalMsg = msg[0:numBlocks*256]+msgWith0s
	return BinaryToChars(originalMsg, errors)


'''================================TESTING======================================'''

if __name__ == "__main__":
	
	msg =  "This program currently works for msgs of any length. It pads the last block of the msg to make the padded msg have a length equal to a multiple of 256 bits."
	print ("ORIGINAL MSG:\n", msg, "\n" )
	print ("ORIGINAL BINARY:\n", CharsToBinary(msg, errors), "\n")


	output = pad(msg)
	print ( "PADDED BINARY:\n", output)

	result = unpad(output)
	print ("\nUNPADDED MSG:\n",result)
