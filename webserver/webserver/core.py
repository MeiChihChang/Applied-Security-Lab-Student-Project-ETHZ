import requests
import urllib
import sys
import json
import os
import jwt
import time
from datetime import datetime, timedelta

from .settings import BASE_DIR

TRUSTED_CERT = os.path.join(BASE_DIR, 'root_cert.pem')

import logging
logger = logging.getLogger(__name__)

# api-endpoint
cert_api = 'https://192.168.33.15:8000/'
db_endpoint = '192.168.33.25:3306'

from django.core.cache import caches
default_cache = caches['default']

from .settings import SECRET_KEY

def generateToken(username):
    access_token = jwt.encode({
        'username': username,
        'exp': datetime.now() + timedelta(seconds=300)
    }, SECRET_KEY, algorithm='HS256').decode('utf-8')

    refresh_token = jwt.encode({
        'username': username,
        'exp': datetime.now() + timedelta(seconds=1800)
    }, SECRET_KEY, algorithm='HS256').decode('utf-8')

    default_cache.set(access_token, refresh_token)
    default_cache.set(refresh_token, access_token)

    return access_token 

def verifyTokenValid(token):
    refresh_token = default_cache.get(token)
    logger.debug("refresh_token: {}".format(refresh_token)) 
    try:
        jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256']) 
    except jwt.ExpiredSignatureError:
        default_cache.delete(token)
        default_cache.delete(refresh_token)
        return False

    try:
        jwt.decode(token, SECRET_KEY, algorithms=['HS256']) 
    except jwt.ExpiredSignatureError:
        return False    

    return True

def getRefreshToken(access_token):
    refresh_token = default_cache.get(access_token)  
    if refresh_token == None:
        return None
    
    try:
        jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256']) 
    except jwt.ExpiredSignatureError:
        default_cache.delete(access_token)
        default_cache.delete(refresh_token)
        return None

    return refresh_token    

def getTokenInfo(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256']) 
    except Exception:
        return None 
    return payload

def generateTokenfromRefreshToken(refresh_token):
    try:
        jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256']) 
    except jwt.ExpiredSignatureError:
        access_token = default_cache.get(refresh_token)
        default_cache.delete(access_token)
        default_cache.delete(refresh_token)
        return None

    payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
    if payload != {}:
        new_access_token = jwt.encode({
            'uuid': payload['uuid'],
            'exp': datetime.now() + timedelta(seconds=1800)
        }, SECRET_KEY, algorithm='HS256').decode('utf-8')
    else:
        return None    
    access_token = default_cache.get(refresh_token)    
    default_cache.delete(access_token)
    default_cache.set(new_access_token, refresh_token)
    return new_access_token

def revokeTokens(token):
    refresh_token = default_cache.get(token)

    default_cache.delete(token)
    default_cache.delete(refresh_token)

def generateCert(username, email, password):
    payload = {
        'uid':username,
        'mail_addr': email,
        'passphrase':password
        }

    r = requests.post(cert_api + 'new_cert', json = payload, verify=TRUSTED_CERT)
    rjson = r.json()

    return rjson, r.status_code

def revokeCert(username):    
    payload = {
        'uid':username
        }

    r = requests.post(cert_api + 'revoke_cert', json = payload, verify=TRUSTED_CERT)
    r = r.json()

    return r, r.status_code

def verifyCert(filename):
    cert = open(filename, 'rt').read()
    payload = {
        'certificate': cert,
        }
    r = requests.post(cert_api + 'verify_cert', json = payload, verify=TRUSTED_CERT)
    r = r.json()

    return r, r.status_code

def getstatusCert():
    r = requests.post(cert_api + 'ca_stats', verify=TRUSTED_CERT)
    r = r.json()

    return r, r.status_code



    


     