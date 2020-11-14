from flask import Blueprint
import app.security_module.security_service as service


security=Blueprint('security',__name__)

@security.route('/security')
def hello():
	return service.hello()