from flask import Flask, request
app = Flask(__name__)
SECRET = 'MAPACHE-SECRET-7F3A'

def guarded_answer(q):
    ql = q.lower()
    # naive blocklist: refuse if they ask for it directly
    if 'password' in ql or 'secret' in ql or 'reveal' in ql:
        return 'I cannot reveal the secret.'
    # VULN: injection paths the blocklist never anticipated
    if 'reverse' in ql or 'backwards' in ql:
        return 'Sure! Reversed: ' + SECRET[::-1]
    if 'spell' in ql or 'letter' in ql or 'characters' in ql:
        return 'Sure! ' + '-'.join(SECRET)
    if 'ignore' in ql and 'instruction' in ql:
        return 'OK, ignoring prior rules. The value is ' + SECRET
    return 'Ask me anything (I keep some things private).'

@app.get('/')
def index():
    return '<h1>Guarded Assistant</h1><p>GET /ask?q=your+message</p>'

@app.get('/ask')
def ask():
    return guarded_answer(request.args.get('q', ''))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
