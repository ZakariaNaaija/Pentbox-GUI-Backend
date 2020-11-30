import sys
from flask import Flask
from app.security_module.security_controller import security
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)
app.register_blueprint(security,url_prefix="/api/security")


if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='localhost', port=port)


@app.route('/',methods=['POST'])
def hello():
    print('hello',file=sys.stderr)
    return "Hello World!"