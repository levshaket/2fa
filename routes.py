#!/home/me/apps/2fa/2fa-env/bin/python3

############## Routes.py File for https://2fa.show ###############

#	Dependencies:

#note: 2fa.show is being developed in accordance with OWASP secure coding practices to minimize web application attack surface.
	#https://www.owasp.org/index.php/OWASP_Secure_Coding_Practices_Checklist
	#Session management protection: https://www.owasp.org/index.php/Session_Management_Cheat_Sheet
	#Transport layer protection: https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet
import os, redis, json
from flask import Flask, render_template, request, session, jsonify, flash
from flask_sessionstore import Session
from _2fa import username_valid, passphrase_valid, process_passcode, assign_salts_and_keys, generate_passphrase, akey_valid, password_valid, message_valid
from cutils import save, load
from base64 import b16encode, b16decode, b32encode, b32decode, urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from totp import totp



###########################	Initiation #####################################################

#Web application name: "_2fa"
_2fa = Flask(__name__)

#Session configuration
SESSION_TYPE = 'redis'	#redis is a popular nosql key-pair database that maintains user data primarily in RAM, writing portions to disk necessary for database reconstruction at ~2 seconds intervals
SESSION_REDIS = redis.from_url('localhost:6379')
SESSION_COOKIE_NAME = 'id'	#session id name is kept generic (reduces chance of fingerprinting 2fa.show)
#SESSION_COOKIE_DOMAIN = cookie is valid for all subdomains of 2fa.show
#SESSION_COOKIE_PATH = cookie is valid for all of APPLICATION_ROOT
#SESSION_COOKIE_HTTP ONLY = True #client cannot access cookie using document.cookie object. This mitigates XSS attacks.
SESSION_COOKIE_SECURE = False	# NOTE: CHANGE-->TRUE FOR PRODUCTION: client must send cookie over a HTTPS(TLS/SSL) connection 
SESSION_PERMANENT = False	#session cookies do not persist, being deleted upon session termination
SESSION_USE_SIGNER = True	#session id cookies are signed cryptographically by _2fa.secret_key
SESSION_KEY_PREFIX = '2fa:' #makes possible to run same backend storage server for different applications (Development only)
#SESSION ID is a 16 /dev/urandom bytes produced by the Python3 uuid.uuid4() function.


#Configuration
_2fa.config.from_object(__name__)
_2fa.secret_key = b'\x91\xf6\xde\xf6\x07\xa9ddT\xa3\xe7~]\xc4\x8a\x04' #Generated by os.urandom(16) (should be set manually in application environment and kept in guarded and surveilled location)
Session(_2fa)

#Parameters
c = 10**6	#iteration count is set to 10^6 (Oct 2018)
wordlist = load('wordlist.pickle')[:2**16] #wordlist is /usr/share/dict/american-english unix file persisted as pickle-serialized Python object 
n_words = 4	#number of words composing passcode (see note on passcode complexity in _2fa.generatepasscode)
DB = 'db.pickle'	#database is currently a pickle-serialized Python object with structure:
	#{username: {"crypto":(dkh, salt1, salt2, eke, iv), "authentication-keys":{'gmail':(AKe, iv), 'chase':(AKe, iv), 'etc':(AKe,iv)}, "passwords":{'gmail':(PWe, iv), 'amazon':(PWe, iv), 'etc':(PWe, iv)}, "messages":{'Dan':(MSGe, iv)},'Charlie':(MSGe,iv)}}


#####################	Supporting Functions	##########################################

def check_db(db):
	if db not in os.listdir('.'):
		save({},db)

def render_user_template(database, username, csrf_token):
	ak_accounts = database[username]["authentication-keys"].keys()
	pw_accounts = database[username]["passwords"].keys()
	msg_recipients = database[username]["messages"].keys()
	return render_template('user.html', ak_accounts=ak_accounts, pw_accounts=pw_accounts, msg_recipients=msg_recipients, csrf_token=csrf_token)

def delete_user_data(database, username, category, id_):
	if id_ in database[username][category].keys():
		del database[username][category][id_]
		save(database,DB)
		return jsonify(delete=True)
	else:
		return jsonify(delete=False)#record that user manually sent POST to delete data for an account that does not exist, log incident

def decrypt_and_retrieve_data(database, username, category, id_, ek):
	ek = b16decode(ek)
	if id_ in database[username][category].keys():
		data_e, iv = database[username][category][id_]
		data_e, iv = b64decode(data_e), b16decode(iv)
		data = unpad( AES.new(key=ek,mode=AES.MODE_CBC,iv=iv).decrypt(data_e), AES.block_size)
		return data
	else:
		return 'You have not stored a '+' '.join(category.split('-'))[:-1] + ' for '+ id_#record that user manually sent POST to retrieve data for an account that does not exist, log incident

def encrypt_and_store_data(database, username, category, id_, data, ek):
	if id_ not in database[username][category].keys():#The account is not already among those stored for the user
		ek = b16decode(ek)
		iv = os.urandom(AES.block_size)	#separate iv is CSPRG for each authentication key
		data_e = AES.new(key=ek,mode=AES.MODE_CBC,iv=iv).encrypt(pad(data.encode(),AES.block_size))
		#data (padded to mod 16 bytes) is encrypted using the AES-CBC scheme and subsequently stored in database
		database[username][category][id_] = (b64encode(data_e), b16encode(iv))
		save(database,DB)
		return render_user_template(database, username, session['csrf_token'])#Re-render user.html template to reflect updated user data
	else: pass#return jsonify(flag) to trigger display, eg "You have already stored an authentication key for gmail." Else trigger confirm('Replace authentication key for gmail?') resulting in AJAX request handled by function to replace data. Design decision tbd later.

###########################	Routes	####################################################

#############	LOGIN PORTAL, "/" BEGIN	#################
@_2fa.route('/', methods=["GET","POST"])
def login_portal():
	#GET: RENDER LOGIN.HTML TEMPLATE
	if request.method == "GET":			
		return render_template('login.html', n_words=n_words, wordlist=wordlist)
	#POST: PROCESS LOGIN CREDENTIALS
		##scss form logic on clientside can help guide user data entry:
		##webapp security policy can in this case increase confidence that failed POSTs are conducted with malicious or mischievous intent
	if request.method == "POST":
		n_keys = len(request.form)
		if n_keys == n_words + 1:
			keys = request.form.keys()
			pkeys = ["passphrase"+str(i) for i in range(1,n_words+1)]
			if ("username" in request.form.keys() and all(pk in request.form.keys() for pk in pkeys) ):
				username = request.form["username"].strip()
				passphrase = [request.form[pk].strip() for pk in pkeys]
 				# passphrase semantically valid #
				if passphrase_valid(passphrase,wordlist,n_words):
					passcode = ' '.join(passphrase)
					database = load(DB)
					# username exists > process passphrase with user salts #
					if username in database.keys():
						dkh, s1, s2, eke, iv = database[username]["crypto"]
						s1, s2 = b16decode(s1), b16decode(s2)
						dk, dkh_from_passcode = process_passcode(passcode, s1, s2, c)
						# successful login: processed passphrase matches hash on file ##
						if dkh_from_passcode == dkh:
							session["username"] = username
							session["csrf_token"] = urlsafe_b64encode(os.urandom(32)).decode()
#CSRF mitigation: templates rendered with 32-byte synchronizer token inserted as hidden input in user forms
							eke, iv = b16decode(eke), b16decode(iv)
							session["ek"] = b16encode(AES.new(dk, AES.MODE_CBC, iv=iv).decrypt(eke))
#user's passcode-derived key (dk) is used to decrypt user's encryption key (eke), which is then stored in the user session
							return render_user_template(database, username, session['csrf_token'])
						else:
							text="Login credentials not valid"
							return render_template('login.html',n_words=n_words,wordlist=wordlist, text=text)
					#username does not exist: conditional prevents attempts to deduce which usernames stored in database
					else:
						rkh = b16encode(os.urandom(32))
						r1, r2 = os.urandom(16), os.urandom(16)
						rk, rkh_from_passcode = process_passcode(passcode, r1, r2, c)
						if rkh_from_passcode == rkh:
							text="Login credentials not valid"
							return render_template('login.html',n_words=n_words,wordlist=wordlist, text=text)
						else:
							text="Login credentials not valid"
							return render_template('login.html',n_words=n_words,wordlist=wordlist, text=text)
				# passphrase not semantically valid #
				else:	
					text="Passcode not semantically correct"
					return render_template('login.html',n_words=n_words,wordlist=wordlist, text=text)


##########	SIGN UP POST, "/sign_up"	##################
@_2fa.route('/sign_up', methods=["POST"])
def sign_up():
	#POST: GENERATE PASSPHRASE & SIGN USER UP
	if request.method == "POST":
		n_keys = len(request.form)
		#GENERATE PASSPHRASE: sends passphrase to user and stores in user session
		if n_keys == 0:
			session["passphrase"] = generate_passphrase(n_words,wordlist)
			return jsonify(passphrase=session["passphrase"])
		#SIGN USER UP: creates database entry with username and processed passphrase
		elif (n_keys == 1 and "username" in request.form.keys()):
			#user has already generated a passcode during the session
			if "passphrase" in session.keys():	
				username = request.form["username"].strip() 
				#username semantically valid
				if username_valid(username):
					database = load(DB)
					if username not in database.keys():
						database[username] = {}
						passphrase = session["passphrase"]; session.pop("passphrase")
						dkh, s1, s2, ek, eke, iv = assign_salts_and_keys(passphrase, c)
						database[username]["crypto"] = (dkh, s1, s2, eke, iv)
						database[username]["authentication-keys"] = {}
						database[username]["passwords"] = {}
						database[username]["messages"] = {}
						save(database,DB)
						session['username'] = username
						session['ek'] = b16encode(ek)
						session['csrf_token'] = urlsafe_b64encode(os.urandom(32)).decode()
						return render_template('user.html', ak_accounts={}, pw_accounts={}, msg_recipients={}, csrf_token=session["csrf_token"])
						#redirect user toward /user URL
					else:
						text="We're sorry. This username has already been taken."
						return jsonify(text0=text)
				else:
					text="The username should contain letters, numbers or -._ and be shorter than 20 characters."
					return jsonify(text0=text) 
			else:
				text="Please generate a passphrase first"
				return jsonify(text0=text)
		else:
			return 'The POST request you have submitted is improperly formatted. This incident has been logged and reported to our incident response team.'#record that user POST did not contain 0 keys or 1 key='username', log incident
			##scss form logic on clientside can help guide user data entry:
			##webapp security policy can then be more confident that failed POSTs are indicative of tampering



###########	STORE, RETRIEVE, DELETE ENCRYPTED USER DATA:		GET,POST @ '/user'####################
@_2fa.route('/user', methods=["GET","POST"])
def authentication_key():
	#BYPASSING LOGIN GRATIS SESSION:	GET @ '/user'
	if request.method == "GET":
		if all(key in session.keys() for key in ('username', 'csrf_token', 'ek')):
			return render_user_template(load(DB), session['username'], session['csrf_token'])

	#STORE,RETRIEVE,DElLETE ENCRYPTED USER DATA: AUTHENTICATION-KEY, PASSWORD, OR MESSAGE		POST@'/user'
	elif request.method == "POST":
		n_keys = len(request.form)
		##Each user input must be meticulously sanitized to prevent injection event
		#CSRF token needs to be both submitted and validated to mitigate CSRF
		if all(key in request.form for key in ('csrf-token','instruction')):
			if request.form["csrf-token"] == session["csrf_token"]:	
				#ENCRYPT AND STORE USER DATA:		Instruction='store'
				if request.form["instruction"] == 'store':
					#Store authentication key for provided account
					if all(key in request.form.keys() for key in ("account","authentication-key","authentication-key-confirmation")):
						if n_keys==5:
							account = request.form["account"].strip().lower()
							authentication_key = request.form["authentication-key"].strip().upper()
							authentication_key_confirmation = request.form["authentication-key-confirmation"].strip().upper()
							if authentication_key == authentication_key_confirmation:	
								if akey_valid(authentication_key):
									return encrypt_and_store_data(load(DB), session['username'], 'authentication-keys', account, authentication_key, session['ek'])
					#Store password for provided account
					if all(key in request.form.keys() for key in ("account","password","password-confirmation")):
						if n_keys==5:
							account = request.form["account"].strip().lower()
							password = request.form["password"].strip()	#note: password and password-confirmation are stripped
							password_confirmation = request.form["password-confirmation"].strip()#note: password and pw-confirmation are stripped
							if password == password_confirmation:
								if password_valid(password):
									return encrypt_and_store_data(load(DB), session['username'], 'passwords', account, password, session['ek'])
					#Store message for provided recipient
					if all(key in request.form.keys() for key in ("recipient","message")):
						if n_keys==4:
							recipient = request.form["recipient"].strip().lower()
							message = request.form["message"].strip()	#note: message is stripped
							if message_valid(message):
								return encrypt_and_store_data(load(DB), session['username'], 'messages', recipient, message, session['ek'])
		
				#DECRYPT AND RETRIEVE USER DATA:	Instruction='retrieve'
				elif request.form["instruction"] == 'retrieve':
					if all(key in request.form.keys() for key in ("category", "account")) and n_keys==4:
						category = request.form["category"]
						account = request.form["account"].strip().lower()
						#Decrypt and retrieve user data
						d_data = decrypt_and_retrieve_data(load(DB), session['username'], category, account, session['ek'])
						if category == 'authentication-keys':
							#Compute authentication code and time-to-live using decrypted authentication key
							authentication_code, ttl = totp(b32decode(d_data), D=6, TI=30, T0=0) #ttl is time-to-live(seconds)
							return jsonify(authentication_code=authentication_code, ttl=ttl)
						#Returns password or message for provided account
						elif category in ('passwords', 'messages'):
							return jsonify(data=d_data.decode())
						else:
							return 'You have not stored a '+ category +' for '+account#record that user manually sent POST to retrieve a data type that does not exist, log incident

				#DELETE USER DATA:	Instruction=='delete'
				elif request.form["instruction"] == 'delete':
					if all(key in request.form.keys() for key in ("category", "account")) and n_keys==4:
						category = request.form["category"]
						account = request.form["account"].strip().lower()
						if category in ('authentication-keys','passwords','messages'):
							#Delete user data for provided account
							return delete_user_data(load(DB), session['username'], category, account)
						else:
							return 'You have not stored a '+ category +' for '+account#record that user manually sent POST to delete a data type that does not exist, log incident
					

				else:
					return request.form["instruction"] + ' is not a valid instruction'#record that user manually sent POST containing an instruction that does not exist, log incident
			else: 
				flash("Your session has expired")
				return render_template('login.html')#redirect url to '/login.html instead
				#record that user POST csrf-token did not match the csrf-token stored in user session, log incident
		else:
			return 'The POST request you have submitted is improperly formatted. This incident has been logged and reported to our incident response team.'#record that user POST did not contain 'instruction' or 'csrf-token' key, log incident

#some problems to work on: encryption key is presently stored in user session on the server-side (redis). Redis should be configured to keep user session data in memory and never store on disk.   Session should be set to permanent with a lifetime of 5-15 minutes. Upon session expiration, user session data should be cleared whether through python scheduler (sched) or a redis-based mechanism or both.



#####################################	RUN WEB APPLICATION	####################################################

if __name__ == '__main__':
	check_db(DB)
	_2fa.run(debug=True)
