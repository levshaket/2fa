################# 	_2fa (Python3) Module: Server-side functions for https://2fa.show 	#####################


import os, re
from hashlib import pbkdf2_hmac
from base64 import b16encode
from Cryptodome.Cipher import AES


# generate passphrase
def generate_passphrase(n_words, wordlist):	#passphrase is created by obtaining CSPR bytes from /dev/urandom, converting the 2-byte value to an unsigned integer 0 to 65535, and selecting a word from the provided wordlist (len >= 65536) using the unsigned integer as an index. The cardinality of the search space for a passphrase using this method is given by |S| = P( |wordspace|, n_words). For n_words = 4,  |wordspace| = 65536,  passphrase_complexity =~ 1.8e19		#Oct 2018
	while True:
		passphrase = [wordlist[int.from_bytes(os.urandom(2),'little')] for i in range(n_words)]
		if len(passphrase) == len(set(passphrase)):
			passphrase = ' '.join(passphrase)
			return passphrase

# process passphrase
def process_passcode(passphrase, salt1, salt2, c):
	pp = passphrase.encode("utf-8")
	dk = pbkdf2_hmac('sha256', pp, salt1, c)
	dkh = pbkdf2_hmac('sha256', dk, salt2, c)
	dkh = b16encode(dkh)
	return (dk, dkh)


# assign hash, salts and keys
def assign_salts_and_keys(passphrase, c):
	s1 = os.urandom(16); s2 = os.urandom(16)	#each salt is 16-bytes, assigned from a CSPR byte pool by /dev/urandom
	ek = os.urandom(32); iv = os.urandom(16)	#encryption key (ek) and initialization vector (iv) are 32 and 16 bytes assigned by /dev/urandom
	dk, dkh = process_passcode(passphrase, s1, s2, c)	#passcode is used to derive key; derived key is hashed
	eke = AES.new(key=dk, mode=AES.MODE_CBC, iv=iv).encrypt(ek)	#derived key is used to encrypt CSPRG user encryption key
	return (dkh, b16encode(s1), b16encode(s2), ek, b16encode(eke), b16encode(iv))
	# note on /dev/urandom, the CSPRNG device used for the separate generation of each salt as well as the encryption key for each user:
		# /dev/urandom in the security community and beyond is well characterized as a pseudorandom number generator (PRNG) acceptable for 	cryptographically secure (CS) use. The Python3.7.1(+) function os.urandom() is used in blocking mode on Unix-like systems, i.e. it prompts python3.7.1(+) to block system calls by other processes to /dev/urandom until 128 bits of entropy are collected, then releases the block.


# encrypt or decrypt encryption key (ek) using key derived from passcode (dk)

#AES is a symmetric block cipher, defined in NIST 197. It is used in Ciphertext Block Chaining (CBC) mode, as further specified in NIST SP 800-38A, section 6.2. In CBC mode, the plaintext is first (if necessary) padded to a multiple of 16-bytes. Then each plaintext block (of 16-bytes) is XOR-ed with the previous ciphertext block prior to encryption.



###############	server-side user data entry validation	#######################################

#scss rules should be implemented for posted forms
#note: upstream user data entry validation needs to be implemented by web server and application server

#username valid
def username_valid(username):
	if len(username) <= 20:	#username must be less than 20 characters and comprise only letters, numbers, and (.-_)
		if all(character in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_.-0123456789' for character in username): 
			return True
#passphrase valid
def passphrase_valid(passphrase,wordlist,n_words):
	#valid passphrases comprise n unique words, each of which is drawn from wordlist
	if len(passphrase)==n_words and len(set(passphrase))==n_words:
		if all(word in wordlist for word in passphrase):
			return True

#stored authentication-key valid
def akey_valid(authentication_key):
	ak_len = len(authentication_key)
	if ak_len in (16,24,32):#The authentication key must be 16,24,or 32 digits. 
		if all(character in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for character in authentication_key):#The authentication key must be formatted in Base32[RFC3548]
			return True
#stored password valid (more sophisticated criteria required)
def password_valid(password):
	if len(password) <= 20:
		characters = '''~`!@#$%^&*()-_=+[]{}\|;:'",.<>/? ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'''
		if all(character in characters for character in password):
			return True
#stored message valid (more sophisticated criteria required)
def message_valid(message):
	if len(message) <= 400:
		characters = '''~`!@#$%^&*()-_=+[]{}\|;:'",.<>/? ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'''
		if all(character in characters for character in message):
			return True

