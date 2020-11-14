from flask import Flask
from app.security_module.security_controller import security
app = Flask(__name__)
app.register_blueprint(security)

@app.route('/')
def hello():
    return "Hello World!"