from flask import Blueprint, request, jsonify, make_response
import app.security_module.security_service as service
from random import SystemRandom

security = Blueprint('security', __name__)


@security.route('/asymetrique/verify', methods=['POST'])
def asym_verify():
    data = request.get_json()
    if data is None or (not 'encrypted' in data and not 'signer_public_key' in data):
        return make_response('Bad request', 400)
    encrypted = data['encrypted']
    signer_public_key = data['signer_public_key']
    if (len(encrypted) > 0):
        result = service.asym_verify(encrypted, signer_public_key)
        return jsonify({'result': result})
    return ''


@security.route('/asymetrique/sign', methods=['POST'])
def asym_sign():
    data = request.get_json()
    if data is None or (not 'message' in data and not 'local_private_key_data' in data and not 'passphrase' in data):
        return make_response('Bad request', 400)
    message = data['message']
    passphrase = data['passphrase']
    local_private_key_data = data['local_private_key_data']
    if (len(message) > 0):
        result = service.asym_sign(message, passphrase,local_private_key_data)
        return jsonify({'result': result})
    return ''


@security.route('/asymetrique/chiffrer', methods=['POST'])
def asym_chiffrer():
    data = request.get_json()
    if data is None or (not 'message' in data and not 'recipient_public_key_data' in data):
        return make_response('Bad request', 400)
    message = data['message']
    recipient_public_key_data = data['recipient_public_key_data']
    if (len(message) > 0):
        result = service.asym_chiffrer(message, recipient_public_key_data)
        return jsonify({'result': result})
    return ''


@security.route('/asymetrique/dechiffrer', methods=['POST'])
def asym_dechiffrer():
    data = request.get_json()
    if data is None or (not 'encrypted' in data and not 'passphrase' in data and not 'local_private_key_data' in data):
        return make_response('Bad request', 400)
    encrypted = data['encrypted']
    passphrase = data['passphrase']
    local_private_key_data = data['local_private_key_data']
    if len(encrypted) > 0:
        result = service.asym_dechiffrer(encrypted, passphrase,local_private_key_data)
        return jsonify({'result': result})
    return ''


@security.route('/asymetrique/genkeys', methods=['POST'])
def asym_gen_keys():
    data = request.get_json()
    if data is None or (not 'passphrase' in data and 'algorithm' in data):
        return make_response('Bad request', 400)
    passphrase = data['passphrase']
    algorithm = data['algorithm']
    result = service.gen_keys(request.remote_addr,passphrase,algorithm)
    return jsonify({'secret': result[0],'public':result[1], 'fingerprint':result[2]})

@security.route('/asymetrique/import',methods=['POST'])
def import_key():
    data = request.get_json()
    if data is None or (not 'fingerprint' in data):
        return make_response('Bad Request',400)
    pubKey = service.import_key(data['fingerprint'])
    return jsonify({'public':pubKey})

@security.route('/symetrique/chiffrer', methods=['POST'])
def sym_chiffrer():
    data = request.get_json()
    if data is None or (not 'message' in data and not 'algorithm' in data):
        return make_response('Bad request', 400)
    message = data['message']
    algorithm = data['algorithm']
    if not 'password' in data:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        password = "".join(SystemRandom().choice(alphabet) for _ in range(40))
    else:
        password = data['password']

    if len(message) > 0:
        result = service.sym_chiffrer(message, algorithm,password)
        return jsonify({'result': result[0], 'password': result[1]})
    return ''


@security.route('/symetrique/dechiffrer', methods=['POST'])
def sym_dechiffrer():
    data = request.get_json()
    if data is None or (not 'encrypted' in data and not 'password' in data):
        return make_response('Bad request', 400)
    encrypted = data['encrypted']
    password = data['password']
    if (len(encrypted) > 0):
        result = service.sym_dechiffrer(encrypted, password)
        return jsonify({'result': result})
    return ''


@security.route('/base64encode', methods=['POST'])
def encode():
    data = request.get_json()
    if (data == None or not 'message' in data):
        return make_response('Bad request', 400)
    message = data['message']
    if (len(message) > 0):
        return jsonify({'result': service.encode(message)})
    return ''


@security.route('/base64decode', methods=['POST'])
def decode():
    data = request.get_json()
    if (data == None or not 'message' in data):
        return make_response('Bad request', 400)
    message = data['message']
    if (len(message) > 0):
        return jsonify({'result': service.decode(message)})
    return ''


@security.route('/hash', methods=['POST'])
def hash():
    data = request.get_json()
    if (data == None or not 'message' in data or not 'algorithm' in data):
        return make_response('Bad request', 400)
    message = data['message']
    if (len(message) > 0):
        return jsonify({'hash': service.hasher(message, data['algorithm'])})
    return ''


@security.route('/crack/bruteforce', methods=['POST'])
def crackBruteForce():
    data = request.get_json()
    print(data)
    if (data == None or not 'message' in data or not 'algorithm' in data):
        return make_response('Bad request', 400)
    message = data['message']
    if (len(message) > 0):
        l = data['length'] if 'length' in data and data['length'] <= 5 else 5
        password = service.bruteForce(message, data['algorithm'], l)
        if (password == None):
            return jsonify({'password': 'Password Not Found'})
        else:
            return jsonify({'password': password})
    return make_response('Empty message', 400)


@security.route('/crack/dictionary', methods=['POST'])
def crackDictionary():
    data = request.get_json()
    if (data == None or not 'message' in data or not 'algorithm' in data):
        return make_response('Bad request', 400)
    message = data['message']
    if (len(message) > 0):
        dic = data['dictionary'] if 'dictionary' in data else None
        password = service.dictionaryAttack(message, data['algorithm'], dic)
        if (password == None):
            return jsonify({'password': 'Password Not Found'})
        else:
            return jsonify({'password': password})
    return make_response('Empty message', 400)


@security.route('/crack/hybrid', methods=['POST'])
def crackHybrid():
    data = request.get_json()
    if (data == None or not 'message' in data or not 'algorithm' in data):
        return make_response('Bad request', 400)
    message = data['message']
    if (len(message) > 0):
        dic = data['dictionary'] if 'dictionary' in data else None
        l = data['length'] if 'length' in data else 2
        password = service.hybridAttack(message, data['algorithm'], l, dic)
        if (password == None):
            return jsonify({'password': 'Password Not Found'})
        else:
            return jsonify({'password': password})
    return make_response('Empty message', 400)
