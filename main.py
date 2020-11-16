import sys
from flask import Flask
from app.security_module.security_controller import security
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.register_blueprint(security,url_prefix="/api/security")

@app.route('/')
def hello():
    print('hello',file=sys.stderr)
    return "Hello World!"