import os
from flask import Flask, request
app = Flask(__name__)

PAGE = ('<h1>NetOps Diagnostics Console</h1>'
        '<form action="/diag"><input name="host" value="127.0.0.1">' 
        '<button>ping</button></form>')

@app.get('/')
def index():
    return PAGE

@app.get('/diag')
def diag():
    host = request.args.get('host', '127.0.0.1')
    # VULN: user input concatenated straight into a shell command (CWE-78)
    out = os.popen('ping -c 1 ' + host).read()
    return '<pre>' + out + '</pre>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
