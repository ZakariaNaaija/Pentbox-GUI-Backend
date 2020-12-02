from itertools import product
import hashlib
import gnupg,base64
gpg = gnupg.GPG(gpgbinary="C:\Program Files (x86)\gnupg\\bin\gpg.exe")


def sym_chiffrer(message,algorithm,password):
	cipher = gpg.encrypt(message, recipients=None, symmetric=algorithm, passphrase=password)
	return (base64.b64encode(str(cipher).encode()).decode(),password)


def sym_dechiffrer(encrypted,password):
	message = base64.b64decode(encrypted).decode()
	decrypted = str(gpg.decrypt(message, passphrase=password))
	return decrypted if decrypted != '' else "passphrase wrong"

def asym_chiffrer(message,algorithm,password):
	"""input_data = gpg.gen_key_input()
	key = gpg.gen_key(input_data)
	#passphrase li hne howa eli t3adih lel decrypt mta3 message
	ascii_armored_public_keys = gpg.export_keys(str(key),passphrase="zakaria")  # same as gpg.export_keys(keyids, False)
	#ascii_armored_private_keys = gpg.export_keys(str(key), True,passphrase="zakaria")
	print(ascii_armored_public_keys)
	#print(ascii_armored_private_keys)
	public_keys = gpg.list_keys()  # same as gpg.list_keys(False)
	private_keys = gpg.list_keys(True)
	print(public_keys)
	print(private_keys)
	cipher = gpg.encrypt(message, recipients="zakaria@DESKTOP-J6K0MMS", passphrase=password)
	print(str(cipher))
	return (base64.b64encode(str(cipher).encode()).decode(),password)
	"""
	return ("","")


def asym_dechiffrer(encrypted,password):
	"""	public_keys = gpg.list_keys()  # same as gpg.list_keys(False)
	private_keys = gpg.list_keys(True)
	print(public_keys)
	print(private_keys)
	message = base64.b64decode(encrypted).decode()
	print(message)
	decrypted = gpg.decrypt(message, passphrase=password)
	print(decrypted.status)
	print(str(decrypted),"hi")
	return str(decrypted) if str(decrypted) != '' else "passphrase wrong"
	"""
	return ("","")


def encode(message):
	return base64.b64encode(message.encode('ascii')).decode('ascii')

def decode(message):
	return base64.b64decode(message.encode('ascii')).decode('ascii')

def hasher(message,algorithm):
	h=hashlib.new(algorithm)
	h.update(message.encode())
	return h.hexdigest()


def bruteForce(hashed,algorithm,maxLength):
	chars="abcdefghijklmnopqrstuvwxyz"
	candidatePass=None
	hasher=hashlib.new(algorithm)
	i =1
	while(i<=maxLength):
		#Effectuer le produit cartésien des caractères i fois 
		for x in product(chars,repeat=i):
		#Le résultat de product est une liste qu'on va parcourir
		#contenant des listes de caractères donc on utilise join pour les concatiner dans une seule chaine
			candidatePass=''.join(x)
			h=hasher.copy()
			h.update(candidatePass.encode())
			if(hashed==h.hexdigest()):
				del h
				return candidatePass
			del h
			#h.update() ajoute la chaine passée en param aux chaines précédente donc on doit créer un nouveau h pour chaque essai
		i=i+1
	return None


def dictionaryAttack(hashed,algorithm,dic):
	hasher=hashlib.new(algorithm)
	try:
		f=open(dic,'r')
	except:
		f=open('app/security_module/dictionaries/words.txt','r')
	f1=f.readlines()
	for x in f1:
		#On enlève l'anti slash n 
		x=x[:-1]
		h=hasher.copy()
		h.update(x.encode())
		if(hashed==h.hexdigest()):
			del h
			return x
		del h
	return None


def hybridAttack(hashed,algorithm,maxLength,dic):
	hasher=hashlib.new(algorithm)
	nums='0123456789'
	try:
		f=open(dic,'r')
	except:
		f=open('app/security_module/dictionaries/words.txt','r')
	f1=f.readlines()
	for x in f1:
		x=x[:-1]
		i=1
		while(i<=maxLength):
			for n in product(nums,repeat=i):
				p=''.join(n)
				candidatePass=x+p
				h=hasher.copy()
				h.update(candidatePass.encode())
				if(hashed==h.hexdigest()):
					del h
					return candidatePass
				del h
			i=i+1
	return None
