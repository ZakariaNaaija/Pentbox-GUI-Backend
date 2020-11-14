import base64
import hashlib
from itertools import product


def encode(message):
	return base64.b64encode(message.encode('ascii')).decode('ascii')

def decode(message):
	return base64.b64decode(message.encode('ascii')).decode('ascii')

def hasher(message,algorithm):
	h=hashlib.new(algorithm)
	h.update(message.encode())
	return h.hexdigest()

def cracker(data):
	message=data['message']
	h=hashlib.new(data['algorithm'])
	attack=data['attack']
	if (attack=='brute'):
		l=data['length']
		if (l>5):
			l=5
		return bruteForce(message,h,l)
	if (attack=='dictionary'):
		d=None
		if('dictionary' in data):
			d=data['dictionary']
		return dictionaryAttack(message,h,d)
	if (attack=='hybrid'):
		l=data['length']
		d=None
		if (l>2):
			l=2
		if('dictionary' in data):
			d=data['dictionary']
		return hybridAttack(message,h,l,d)
	return None


def bruteForce(hashed,hasher,maxLength):
    chars="abcdefghijklmnopqrstuvwxyz"
    candidatePass=None
    i=1
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

def dictionaryAttack(hashed,hasher,dic):
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

def hybridAttack(hashed,hasher,maxLength,dic):
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