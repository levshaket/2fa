# python version:	3
# module name:		totp
# description:		RFC6238 TOTP: Time-Based One-Time Password Algorithm (produces authentication code based on Key and Unix Time)
# description:		RFC4226 HOTP: HMAC-based One-Time Password Algorithm (produces authentication code based on Key and Incremental Counter)
# description:		TOTP extends HOTP to support the time-based moving factor.
# common usage: 	from totp import totp, hotp

# notes:
	#2factor authentication key-issuing applications typically set D->6, T0->0, and TI->30
	#T0 designates the Unix time at which the counter became active / T0=0 represents the Unix epoch [1970-01-01 00:00:00]
	#TI designates the time interval on which the counter increments / TI=30 results in a new code every 30 seconds
	#D designates the length of the authentication token to be produced / D=6 results in a code such as '048935'

	#The key K formatted to base-32[RFC3548] must be reformatted to a byte string prior to feeding into the HOTP algorithm.




import time, hmac
from hashlib import sha1
from bitstring import BitArray


def counter(T0=0, TI=30):
	t = time.time()	#the current time in seconds since the Unix epoch [1970-01-01 00:00:00]
	n = int((t-T0)/TI) #the counter number since the Unix time designated by T0
	tr = TI - (t-T0) % TI	#the time remaining in seconds until n increments
	return (n,tr)

def hotp(K, n, D=6):
	n = n.to_bytes(8,'big')	#the counter formatted in base 10 is reformatted to an 8-byte sequence
	ho = hmac.new(K,n,sha1) #the key and counter are fed into the HMAC-SHA1 algorithm [RFC2104] to produce a HMAC hash object
	h = BitArray(ho.digest())	#the HMAC hash object is digested and the hash value is stored in a BitArray class
	o = h[-4:].uint	#the offset value [0-15] is the decimal representation of the four least-significant bits
	i = h[8*o+1: 8*o+32].uint	#the integer i is the decimal representation of the 31 bit-number starting at bit position 8*o+1
	token = i % 10**D	#the token is the least significant D digits of i
	return token

def totp(K, D=6, TI=30, T0=0):
	n, tr = counter(T0,TI)
	token = hotp(K,n,D)	#the counter number and key byte string are fed into the HOTP algorithm [RFC4226]
	token = '{:0{}d}'.format(token,D)	#the authentication token is reformatted as a D-digit string, if necessary, '0'-padded to the left
	return (token, tr)	#token and time remaining until a new token becomes valid are returned
