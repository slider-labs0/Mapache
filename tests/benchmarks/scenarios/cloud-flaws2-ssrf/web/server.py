import requests
from flask import Flask, request
app = Flask(__name__)

@app.get('/')
def index():
    return ('<h1>Image Proxy</h1><form action="/fetch">'
            '<input name="url" size=60 value="http://example.com">'
            '<button>fetch</button></form>')

@app.get('/fetch')
def fetch():
    url = request.args.get('url', '')
    # VULN: no destination validation -> SSRF to internal metadata (CWE-918)
    try:
        r = requests.get(url, timeout=3)
        return '<pre>' + r.text + '</pre>'
    except Exception as e:
        return 'error: %r' % e

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
