from flask import Flask, request, Response
import base64
app = Flask(__name__)
DEFAULTS = {'tomcat': 'tomcat', 'admin': 'admin'}

@app.get('/')
def index():
    return '<h1>Apache Tomcat/9.0</h1><a href="/manager">Manager App</a>'

@app.get('/manager')
def manager():
    auth = request.authorization
    if auth and DEFAULTS.get(auth.username) == auth.password:
        return ('<h1>Manager App</h1><p>Welcome, %s. Deploy WAR here.</p>'
                % auth.username)
    return Response('Auth required', 401,
                    {'WWW-Authenticate': 'Basic realm="Manager"'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
