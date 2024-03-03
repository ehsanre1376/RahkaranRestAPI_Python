
import requests
import rsa
import json
import binascii
import tempfile
import os
from datetime import datetime

G_session = ""
G_ExpireDate = datetime(2000, 1, 1)
G_protocol = "http"
G_ServerName = "127.0.0.1"
G_ServerPort = "80"
G_RahkaranName = "PortfolioDEV"
G_BaseURL = G_protocol + "://" + G_ServerName + ":" + "80" + "/" + G_RahkaranName
G_AuthenticationName = "sg-auth-"
G_UserName = ""
G_PassWord = ""

class RahkaranLogin:
    
    def __init__(self, user_name="admin", password="admin"):
        global G_ExpireDate
        global G_AuthenticationName
        global G_RahkaranName
        if G_ExpireDate < datetime.now():
            try:
                with open(
                    os.path.join(
                        tempfile.gettempdir(), G_AuthenticationName + G_RahkaranName + ".txt"
                    ),
                    "r",
                    encoding="utf-8",
                ) as file:
                    content = file.readlines()
                    G_session = content[0]
                    G_ExpireDate = datetime.strptime(content[1].strip(), "%d-%b-%Y %H:%M:%S")
            except FileNotFoundError:
                print(f"The file {os.path.join(
                        tempfile.gettempdir(), G_AuthenticationName + G_RahkaranName + ".txt"
                    )} does not exist.")
            except IOError:
                print("An error occurred while trying to read the file.")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")

    @staticmethod
    def hex_string_to_bytes(hex_string):
        return binascii.unhexlify(hex_string)

    @staticmethod
    def bytes_to_hex_string(byte_array):
        return binascii.hexlify(byte_array).decode()

    def login(self):

        if datetime.now() < G_ExpireDate:
            return self.G_session, self.G_ExpireDate
        url = self.G_BaseURL + "/Services/Framework/AuthenticationService.svc"
        session_url = url + "/session"
        login_url = url + "/login"

        response = requests.get(session_url, timeout=10)
        if response.status_code != 200:
            raise ValueError(f"GET /session {response.status_code}")
        session = json.loads(response.text)
        m = self.hex_string_to_bytes(session["rsa"]["M"])
        e = self.hex_string_to_bytes(session["rsa"]["E"])
        rsa_key = rsa.PublicKey(
            int.from_bytes(m, byteorder="big"), int.from_bytes(e, byteorder="big")
        )
        session_plus_password = session["id"] + "**" + self.G_PassWord
        encrypted_password = rsa.encrypt(session_plus_password.encode(), rsa_key)
        headers = {"content-Type": "application/json"}
        data = {
            "sessionId": session["id"],
            "username": self.G_UserName,
            "password": self.bytes_to_hex_string(encrypted_password),
        }
        response = requests.post(
            login_url, headers=headers, data=json.dumps(data), timeout=10
        )
        if response.status_code != 200:
            raise ValueError(f"POST /login {response.status_code}")
        session = response.headers["Set-Cookie"].split(",")[2].split(";")[0].strip()
        ExpireDate = response.headers["Set-Cookie"].split(",")[1].split(";")[0].strip()
        ExpireDate = datetime.strptime(ExpireDate, "%d-%b-%Y %H:%M:%S %Z")
        self.G_session = session
        self.G_ExpireDate = ExpireDate
        with open(
            os.path.join(
                tempfile.gettempdir(), self.G_AuthenticationName + self.G_RahkaranName + ".txt"
            ),
            "w",
            encoding="utf-8",
        ) as f:
            f.write(self.G_session+"\n" )
            f.write(self.G_ExpireDate.strftime("%d-%b-%Y %H:%M:%S %Z"))
        return session, ExpireDate

# Create an instance of the class
rahkaran_login = RahkaranLogin()

# Call the login method
session, ExpireDate = rahkaran_login.login()

print(session, ExpireDate)
