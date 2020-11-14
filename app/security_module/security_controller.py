import sys
from flask import Blueprint,request,jsonify,make_response
import app.security_module.security_service as service


security=Blueprint('security',__name__)

@security.route('/base64encode',methods=['POST'])
def encode():
	data=request.get_json()
	if (data==None or not 'message' in data):
		return make_response('Bad request',400)
	message=data['message']
	if (len(message)>0):
		return jsonify({'result': service.encode(message)})
	return ''

@security.route('/base64decode',methods=['POST'])
def decode():
	data=request.get_json()
	if (data==None or not 'message' in data):
		return make_response('Bad request',400)
	message=data['message']
	if (len(message)>0):
		return jsonify({'result': service.decode(message)})
	return ''

@security.route('/hash',methods=['POST'])
def hash():
	data=request.get_json()
	if (data==None or not 'message' in data or not 'algorithm' in data):
		return make_response('Bad request',400)
	message=data['message']
	if (len(message)>0):
		return jsonify({'hash':service.hasher(message,data['algorithm'])})
	return ''

@security.route('/crack',methods=['POST'])
def crack():
	data=request.get_json()
	if (data==None or not 'message' in data or not 'algorithm' in data or not 'attack' in data):
		return make_response('Bad request',400)
	message=data['message']
	if (len(message)>0):
		password=service.cracker(data)
		if (password==None):
			return make_response('Password not found')
		else:
			return jsonify({'password':password})
	return ''
