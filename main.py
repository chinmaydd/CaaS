# Library Imports
from bottle import route, run, template, request, response
import pdb
import os

# Used for generating a random 8 character sequence
import random
import string

# Yet Another Gmail integration library
import yagmail

# Key value database
import pickledb
db = pickledb.load('storage.db', 'False')

# Cryptographic Libraries
from Crypto.Cipher import AES
import hashlib
import hkdf

# Character interchange
import base64
import binascii

# CaaS master key
Xp = '00010011101111000000001010011101'

# Function checks if the user already exists in the database and returns true if does, false otherwise
def user_exists(email_addr):
    val = db.get(email_addr)

    # Check return value of the query
    if val:
        return True
    else:
        return False

# Function which verifies the user

def verify_user(email_addr, secure_string):
    # Get value from the database
    val = db.get(email_addr)
    print val
    # Check if the secure string sent is the same as that in the database
    if val['Secure_String'] == secure_string:

        # Set confirmed as true, hence the user is verified.
        val['confirmed'] = 'True'
        db.set(email_addr, val)
        return True
    else:
        return False

# Function handles cases where the user is already verified.
def already_verified(email_addr):
    # Get value from the database
    val = db.get(email_addr)
    # Check if the email address in the database has already been verified
    if val['confirmed'] == True:
        return True
    else:
        return False

# Function registers the user by adding data into the db and sending them a mail for authrntication via EBIA
def register_user(email_addr, password):

    # Create a random string of bytes to send the user via email.
    secure_string = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    # Let us store passwords in plaintext
    db.set(email_addr, {'Password': password, 'confirmed': 'False','ids': [], 'Secure_String': secure_string})

    # Send an email to the user
    # GMail Credentials for CaaS
    yag = yagmail.SMTP("email", "password")
    contents = ["Welcome to CaaS(Confidentiality as a Service Paradigm. Your secret key is " + secure_string + ". Please make a request to /verify with the request formatted as the following JSON: {'Email': email_address, 'Secure_String':secure_string}. If you are verified, you can then login into the CaaS service with the password you provided earlier."]

    yag.send(email_addr, 'CaaS registration', contents)

# Verification function
@route('/verify', method="POST")
def verify():

    # Parse the incoming JSON
    req = request.json

    # Generate the response type
    response.content_type = "application/json"
    rv = dict()

    try:
        email_addr = req['Email']
        secure_string = req['Secure_String']
        
        # Message is different for already verified accounts
        if already_verified(email_addr):
            rv['Status'] = "Already Verified"
            rv['Message'] = "You have already been successfully verified"
        else:
            if verify_user(email_addr, secure_string):
                rv['Status'] = "Successful"
                rv['Message'] = "You have been successfully verified"
            else:
                rv['Status'] = "Unsuccessful"
                rv['Error'] = "Verification failed"

    except Exception as e:
        rv['Status'] = "Unsuccessful"
        rv['Error'] = "Unable to process your request"

    return rv

# Registration function
@route('/register', method="POST")
def register():
    # pdb.set_trace()

    # Parse the incoming JSON
    req = request.json
    email_addr = req['Email']
    password = req['Password']

    # Generate the response type
    response.content_type = "application/json"
    rv = dict()

    # Check if the user exists in the database with the same email address.
    if user_exists(email_addr):

        # Since the user already exists, we return him an unsuccessful error message.
        rv['Status'] = "Unsuccessful"
        rv['Error'] = "User already exists"
    else:
        # Email address was not found in the database. Ask the user to check his/her email.
        rv['Status'] = "Successful"
        rv['Message'] = "Registration was successful, please confirm your identity via email"
        register_user(email_addr, password)

    return rv

# +cLayerRemote [Encryption]
@route('/encrypt', method="POST")
def encrypt():
    req = request.json
    CaaS_creds = req['CaaS_creds']
    UserList = req['UserList']
    ciphertext = base64.b64decode(req['Ciphertext'])

    response.content_type = "application/json"
    rv = dict()

    # Abort if any of the people in the list don't have CaaS accounts
    for user in UserList:
        if not user_exists(user):
            rv['Status'] = "Unsuccessful"
            rv['Error'] = "User {0} not found. Aborted.".format(user)
            return rv

    # Add sender to user list
    UserList.append(CaaS_creds['username'])

    # Sort user list
    UserList = sorted(UserList)

    hashes = ['']

    # Calculate the iterative hashes
    for j in range(len(UserList)):
        s = hashlib.sha512()
        s.update(UserList[j]+hashes[j])
        h = s.hexdigest()
        hashes.append(h)

    # Obtain key via HMAC-based key derivation function (hkdf)
    kdf = hkdf.Hkdf(binascii.unhexlify(hashes[-1]), Xp, hash=hashlib.sha512)
    key = kdf.expand(b"context1", 32)

    ctr = os.urandom(16)
    e = AES.new(key, AES.MODE_CTR, counter=lambda: ctr)
    CaaS_encrypted_text = e.encrypt(ciphertext)
    rv['ctr'] = base64.b64encode(str(ctr))
    rv['enc_p'] = base64.b64encode(CaaS_encrypted_text)
    return rv

# -cLayerRemote [Decryption]
@route('/decrypt', method="POST")
def decrypt():
    req = request.json
    CaaS_creds = req['CaaS_creds']
    UserList = req['UserList']
    ciphertext = base64.b64decode(req['Ciphertext'])
    ctr = base64.b64decode(req['ctr'])

    response.content_type = "application/json"
    rv = dict()

    # Abort if any of the people in the list don't have CaaS accounts
    for user in UserList:
        if not user_exists(user):
            rv['Status'] = "Unsuccessful"
            rv['Error'] = "User {0} not found. Aborted.".format(user)
            return rv

    # Add sender to user list
    UserList.append(CaaS_creds['username'])

    # Sort user list
    UserList = sorted(UserList)

    hashes = ['']

    # Calculate the iterative hashes
    for j in range(len(UserList)):
        s = hashlib.sha512()
        s.update(UserList[j]+hashes[j])
        h = s.hexdigest()
        hashes.append(h)

    # Obtain key via HMAC-based key derivation function (hkdf)
    kdf = hkdf.Hkdf(binascii.unhexlify(hashes[-1]), Xp, hash=hashlib.sha512)
    key = kdf.expand(b"context1", 32)

    e = AES.new(key, AES.MODE_CTR, counter=lambda: ctr)
    CaaS_decrypted_text = e.decrypt(ciphertext)
    rv['dec_p'] = base64.b64encode(CaaS_decrypted_text)
    return rv

run(host='localhost', port=8080)
