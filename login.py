import requests
import rsa
import json
import binascii
from datetime import datetime
G_sessionv =""
G_ExpireDate = datetime(2020, 3, 15)
G_BaseURL = "http://127.0.0.1/PortfolioDEV"
G_UserName ="admin"
G_PassWord = "admin"
def hex_string_to_bytes(hex_string):
    return binascii.unhexlify(hex_string)

def bytes_to_hex_string(byte_array):
    return binascii.hexlify(byte_array).decode()

def login(user_name = G_UserName, password=G_PassWord):
    global G_ExpireDate
    if datetime.now() > G_ExpireDate :
        return G_sessionv,G_ExpireDate
    url = G_BaseURL+"/Services/Framework/AuthenticationService.svc"
    session_url = url + "/session"
    login_url = url + "/login"

    response = requests.get(session_url)
    if response.status_code != 200:
        raise Exception('GET /session {}'.format(response.status_code))
    session = json.loads(response.text)
    m = hex_string_to_bytes(session['rsa']['M'])
    e = hex_string_to_bytes(session['rsa']['E'])
    rsa_key = rsa.PublicKey(int.from_bytes(m, byteorder='big'), int.from_bytes(e, byteorder='big'))
    session_plus_password = session['id'] + "**" + password
    encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)
    headers = {'content-Type': 'application/json'}
    data = {
        'sessionId': session['id'],
        'username': user_name,
        'password': bytes_to_hex_string(encrypted_password)
    }
    response = requests.post(login_url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        raise Exception('POST /login {}'.format(response.status_code))
    session = response.headers['Set-Cookie'].split(',')[2].split(';')[0].strip()
    ExpireDate = response.headers["Set-Cookie"].split(",")[1].split(";")[0].strip()
    ExpireDate = datetime.strptime(ExpireDate, "%d-%b-%Y %H:%M:%S %Z")
    G_session = session
    G_ExpireDate = ExpireDate
    return session,ExpireDate
session,ExpireDate = login()

print(session, ExpireDate)
