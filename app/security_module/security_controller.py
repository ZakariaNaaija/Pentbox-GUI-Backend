from flask import Blueprint, request, jsonify, make_response
import app.security_module.security_service as service

security = Blueprint('security', __name__)


@security.route('/symetrique/chiffrer', methods=['POST'])
def sym_chiffrer():
    data = request.get_json()
    if data is None or (not 'message' in data and not 'algorithm' in data):
        return make_response('Bad request', 400)
    message = data['message']
    algorithm = data['algorithm']
    if (len(message) > 0):
        result = service.sym_chiffrer(message, algorithm)
        return jsonify({'result': result[0], 'password': result[1]})
    return ''


@security.route('/symetrique/dechiffrer', methods=['POST'])
def sym_dechiffrer():
    data = request.get_json()
    if data is None or (not 'encrypted' in data and not 'algorithm' in data and not 'password' in data):
        return make_response('Bad request', 400)
    encrypted = data['encrypted']
    password = data['password']
    algorithm = data['algorithm']
    if (len(encrypted) > 0):
        result = service.sym_dechiffrer(encrypted, algorithm, password)
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
