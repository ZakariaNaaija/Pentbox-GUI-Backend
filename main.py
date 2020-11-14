import sys
from flask import Flask
from app.security_module.security_controller import security
app = Flask(__name__)
app.register_blueprint(security,url_prefix="/api/security")

@app.route('/')
def hello():
    print('hello',file=sys.stderr)
    return "Hello World!"