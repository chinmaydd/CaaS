#!/usr/bin/python
"""Usage: ./client.py [-hced]

Options:
  -h, --help        show this help message 
  -c, --configure   Run first-time configuration
  -e, --encrypt     Run the prePush sequence
  -d, --decrypt     Run the postPull sequence

"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import urllib2
import settings
import base64
import requests
import hashlib
import dropbox
import ast
import os
from docopt import docopt

def prePush(path):
    key = os.urandom(32)
    counter = os.urandom(16)
    plaintext = open(path, 'r').read()
    e = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    ciphertext = e.encrypt(plaintext)
    ciphertext = base64.b64encode(ciphertext)

    username = raw_input("Enter CaaS username: ")
    password = raw_input("Enter CaaS password: ")
    CaaS_creds = {"username": username, "password": password}
    print "Enter recipients (space-separated emails)"
    UserList = raw_input().split(' ')

    r = requests.post('http://localhost:8080/encrypt', json={"CaaS_creds": CaaS_creds, "UserList": UserList, "Ciphertext": ciphertext})
    fromCaaS = ast.literal_eval(r.text)
    ctr = base64.b64decode(fromCaaS['ctr'])
    enc_p = base64.b64decode(fromCaaS['enc_p'])


    d = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    rts = d.decrypt(enc_p)

    # Calculate message digest
    m = hashlib.new("MD5")
    m.update(rts)
    digest = m.digest()

    f = open('encrypted.txt', 'w')
    f.write(base64.b64encode(rts)+"\n")
    f.write(base64.b64encode(ctr)+"\n")
    f.write(base64.b64encode(digest))
    f.close()

    # Upload to Dropbox
    client = dropbox.Dropbox(settings.ACCESS_TOKEN)
    f = open('encrypted.txt', 'rb')
    response = client.put_file('/encrypted.txt', f)
    print "Uploaded: ", response
    print "Share Link: ", client.share('/encrypted.txt', short_url=False)['url'][:-1]+"1"

def postPull(url):
    urlfile = urllib2.urlopen(url)
    contents = urlfile.read().split('\n')
    rts = base64.b64decode(contents[0])
    ctr = base64.b64decode(contents[1])
    digest = base64.b64decode(contents[2])
    username = raw_input("Enter CaaS username: ")
    password = raw_input("Enter CaaS password: ")
    CaaS_creds = {"username": username, "password": password}
    print "Enter participants (space-separated emails)"
    UserList = raw_input().split(' ')

    key = os.urandom(32)
    counterPull = os.urandom(16)
    e = AES.new(key, AES.MODE_CTR, counter=lambda: counterPull)
    ciphertext = e.encrypt(rts)
    ciphertext = base64.b64encode(ciphertext)

    r = requests.post('http://localhost:8080/decrypt', json={"CaaS_creds": CaaS_creds, "UserList": UserList, "ctr": base64.b64encode(ctr), "Ciphertext": ciphertext})
    fromCaaS = ast.literal_eval(r.text)
    dec_p = base64.b64decode(fromCaaS['dec_p'])

    d = AES.new(key, AES.MODE_CTR, counter=lambda: counterPull)
    originalMessage = d.decrypt(dec_p)
    return originalMessage


def configure():
    if settings.APP_KEY == "INSERTAPPKEY":
        print "Please configure APP_KEY in settings.py"
        sys.exit(1)
    if settings.APP_SECRET == "INSERTAPPSECRET":
        print "Please configure APP_SECRET in settings.py"
        sys.exit(1)
    flow = dropbox.oauth.DropboxOAuth2FlowNoRedirect(settings.APP_KEY, settings.APP_SECRET)
    authorize_url = flow.start()

    print '1. Go to: ' + authorize_url
    print '2. Click "Allow" (you might have to log in first)'
    print '3. Copy the authorization code.'
    code = raw_input("Enter the authorization code here: ").strip()

    try:
        access_token, user_id = flow.finish(code)
    except:
        print 'Error: %s' % (e,)
        sys.exit(1)

    f = open('settings.py', 'w')
    f.write("ACCESS_TOKEN = \"" + str(access_token) + "\"\n")
    f.write("USER_ID = " + str(user_id))
    f.close()

def main(docopt_args):
    if docopt_args['--configure']:
        configure()
        print "Configuration successful!"
    elif docopt_args['--encrypt']:
        prePush(raw_input("Enter file path: "))
    elif docopt_args['--decrypt']:
        url = raw_input("Enter Dropbox share link: ")
        originalMessage = postPull(url)
        print originalMessage


if __name__ == '__main__':
    arguments = docopt(__doc__)
    main(arguments)
