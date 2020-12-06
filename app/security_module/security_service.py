from itertools import product
import hashlib
import gnupg, base64
import sys
import os
import io
#gpgbinary="C:\Program Files (x86)\gnupg\\bin\\gpg.exe"
gpg = gnupg.GPG()
fileName = ''


def sym_chiffrer(message, algorithm, password):
    cipher = gpg.encrypt(message, recipients=None, symmetric=algorithm, passphrase=password)
    # return encode(str(cipher)), password
    return str(cipher), password


def sym_dechiffrer(encrypted, password, ip):
    # message = decode(encrypted)
    fileName = "output-"+ip+".txt"
    gpg.verbose = True
    with io.open(fileName, "w+", encoding="utf-8") as sys.stdout:
        decrypted = str(gpg.decrypt(encrypted, passphrase=password))
        sys.stdout.flush()
        sys.stdout.close()
        algorithm = ""
        gpg.verbose = False
    if decrypted != '':
        algorithm = get_algorithm(fileName)
    return (decrypted, algorithm) if decrypted != '' else ('passphrase wrong','')


def gen_keys(ip, passphrase, algorithm):
    input_data = gpg.gen_key_input(key_type=algorithm, key_length=1024, name_real=ip, passphrase=passphrase)
    key = gpg.gen_key(input_data)
    ascii_armored_public_keys = gpg.export_keys(str(key), armor=True)  # same as gpg.export_keys(keyids, False)
    ascii_armored_private_keys = gpg.export_keys(str(key), True, armor=True, passphrase=passphrase)
    secret = encode(ascii_armored_private_keys)
    public = encode(ascii_armored_public_keys)
    fingerprint = key.fingerprint
    gpg.delete_keys(fingerprint, passphrase=passphrase, secret=True)
    return ascii_armored_private_keys, ascii_armored_public_keys, fingerprint


def import_key(fingerprint):
    return gpg.export_keys(fingerprint, armor=True)


def import_own_key(public):
    return gpg.import_keys(public).results[0]['fingerprint']


def delete_keys(fingerprint, passphrase):
    gpg.delete_keys(fingerprint, True, passphrase=passphrase)
    gpg.delete_keys(fingerprint, passphrase=passphrase)


def asym_chiffrer(message, recipient_public_key_data):
    import_result = gpg.import_keys(recipient_public_key_data)
    cipher = gpg.encrypt(message, recipients=key_id(import_result), always_trust=True)
    # print(cipher,file=sys.stdout)
    # gpg.delete_keys(key_id(import_result))
    # return encode(str(cipher))
    return str(cipher)


def asym_dechiffrer(encrypted, passphrase, local_private_key_data,ip):
    # encrypted = decode(encrypted)
    # import_result = gpg.import_keys(decode(local_private_key_data))
    import_result = gpg.import_keys(local_private_key_data)
    fingerprint = key_id(import_result)
    fileName = "output-"+ip+".txt"
    gpg.verbose = True
    with io.open(fileName, "w+", encoding="utf-8") as sys.stdout:
        decrypted = gpg.decrypt(encrypted, passphrase=passphrase)
        sys.stdout.flush()
        sys.stdout.close()
    gpg.verbose = False
    algorithm = get_algorithm(fileName, False)
    gpg.delete_keys(key_id(import_result), secret=True, passphrase=passphrase)
    return (str(decrypted), algorithm) if str(decrypted) != '' else ("passphrase wrong","")


def get_algorithm(fileName, sym=True):
    line = None
    algo = None
    with open(fileName, "r", encoding='utf-8') as file:
        for x in file:
            if x.find('gpg:') > -1:
                line = x
                break
        if line is not None:
            if sym == True:
                algo = (line[4:])
            else:
                algo= (line[4:line.find(',')]).capitalize()
    #os.remove(fileName)
    return algo


def asym_sign(message, passphrase, local_private_key_data):
    import_result = gpg.import_keys(local_private_key_data)
    signed_data = gpg.sign(message, keyid=key_id(import_result),
                           passphrase=passphrase)
    # delete_keys(key_id(import_result),passphrase)
    gpg.delete_keys(key_id(import_result), secret=True, passphrase=passphrase)
    return str(signed_data)


def asym_verify(encrypted, signer_public_key,ip):
    # encrypted = decode(encrypted)
    import_result = gpg.import_keys(signer_public_key)
    fileName = "output-"+ip+".txt"
    gpg.verbose = True
    with io.open(fileName, "w+", encoding="utf-8") as sys.stdout:
        verified = gpg.verify(encrypted)
        sys.stdout.flush()
        sys.stdout.close()
    gpg.verbose = False
    algorithm = get_algorithm(fileName, False)
    # gpg.delete_keys(key_id(import_result))
    return (verified.__dict__['valid'], algorithm) if verified else False  # "Signature could not be verified!"


def key_id(import_result):
    # return import_result.__dict__['results'][0]['fingerprint'][-8:]
    return import_result.results[0]['fingerprint']


def encode(message):
    return base64.b64encode(message.encode('ascii')).decode('ascii')


def decode(message):
    return base64.b64decode(message.encode('ascii')).decode('ascii')


def hasher(message, algorithm):
    h = hashlib.new(algorithm)
    h.update(message.encode())
    return h.hexdigest()


def bruteForce(hashed, algorithm, maxLength):
    chars = "abcdefghijklmnopqrstuvwxyz"
    candidatePass = None
    hasher = hashlib.new(algorithm)
    i = 1
    while (i <= maxLength):
        # Effectuer le produit cartésien des caractères i fois
        for x in product(chars, repeat=i):
            # Le résultat de product est une liste qu'on va parcourir
            # contenant des listes de caractères donc on utilise join pour les concatiner dans une seule chaine
            candidatePass = ''.join(x)
            h = hasher.copy()
            h.update(candidatePass.encode())
            if (hashed == h.hexdigest()):
                del h
                return candidatePass
            del h
        # h.update() ajoute la chaine passée en param aux chaines précédente donc on doit créer un nouveau h pour chaque essai
        i = i + 1
    return None


def dictionaryAttack(hashed, algorithm, dic):
    hasher = hashlib.new(algorithm)
    try:
        f = open(dic, 'r')
    except:
        f = open('app/security_module/dictionaries/words.txt', 'r')
    f1 = f.readlines()
    for x in f1:
        # On enlève l'anti slash n
        x = x[:-1]
        h = hasher.copy()
        h.update(x.encode())
        if (hashed == h.hexdigest()):
            del h
            return x
        del h
    return None


def hybridAttack(hashed, algorithm, maxLength, dic):
    hasher = hashlib.new(algorithm)
    nums = '0123456789'
    try:
        f = open(dic, 'r')
    except:
        f = open('app/security_module/dictionaries/words.txt', 'r')
    f1 = f.readlines()
    for x in f1:
        x = x[:-1]
        i = 1
        while (i <= maxLength):
            for n in product(nums, repeat=i):
                p = ''.join(n)
                candidatePass = x + p
                h = hasher.copy()
                h.update(candidatePass.encode())
                if (hashed == h.hexdigest()):
                    del h
                    return candidatePass
                del h
            i = i + 1
    return None
