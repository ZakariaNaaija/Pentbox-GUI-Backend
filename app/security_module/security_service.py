from itertools import product
import hashlib
import gnupg,base64

def sym_chiffrer(message,password):
	gpg = gnupg.GPG()
	cipher = gpg.encrypt(message, recipients=None, symmetric='AES', passphrase=password)
	return (base64.b64encode(str(cipher).encode()).decode(),password)


def sym_dechiffrer(encrypted,algorithm,password):
	gpg=gnupg.GPG()
	message = base64.b64decode(encrypted).decode()
	decrypted = str(gpg.decrypt(message, passphrase=password))
	return decrypted if decrypted is not '' else "passphrase wrong" 


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
