from flask import Flask
app = Flask(__name__)
CREDS = ('{\n  "AccessKeyId": "ASIAEXAMPLESSRFCREDS",\n'
         '  "SecretAccessKey": "wJalrXUtnFEMI/SSRFLEAKEDbPxRfiCYEXAMPLE",\n'
         '  "Token": "IQoJb3JpZ2luX2VjE...redacted"\n}')

@app.get('/latest/meta-data/iam/security-credentials/')
def role():
    return 'lab-ec2-role'

@app.get('/latest/meta-data/iam/security-credentials/lab-ec2-role')
def creds():
    return CREDS

# also answer the bare host so a naive http://metadata/ probe shows something
@app.get('/')
def root():
    return 'latest\n'

if __name__ == '__main__':
    # listen on port 80 and answer to the hostname 'metadata' / 169.254.169.254
    app.run(host='0.0.0.0', port=80)
