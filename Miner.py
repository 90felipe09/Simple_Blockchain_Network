from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import datetime as d
import json
import socket as s
import base64


PORT_NUMBER = 8080
IP_BOOK = 'localhost'

def load_private_key(deserialized_key):
    private_key = serialization.load_pem_private_key(
                                                 deserialized_key,
                                                 password=None,
                                                 backend=default_backend())

    return private_key

def load_public_key(deserialized_public_key):
    public_key = serialization.load_pem_public_key(deserialized_public_key, default_backend())
    return public_key

def FETCH_request():
    BSP = {}
    BSP['method'] = "FETCH"
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)

    soc = s.socket(s.AF_INET, s.SOCK_STREAM)

    soc.connect((IP_BOOK, PORT_NUMBER))
    soc.send(bytes(BSP_JSON, 'utf-8'))
    msg = soc.recv(1024)
    soc.close()
    return json.loads(msg)

def pegar_bloco():
    response = FETCH_request()
    if (response['response_code'] == 1):
        return False
    else:
        return response['block'], response['public_key']

def minerar_bloco(bloco):
    print(1)

def SOLVE_request(nonce, book_key):
    BSP = {}
    BSP['method'] = "SOLVE"
    BSP['from'] = public_key

    pbk = book_key.encode('utf-8')
    pbk = base64.b64decode(pbk)
    pbk = load_public_key(pbk)

    nonce_crypt = pbk.encrypt(
        str(nonce),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    BSP['nonce'] = nonce_crypt
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)

    soc = s.socket(s.AF_INET, s.SOCK_STREAM)

    soc.connect((IP_BOOK, PORT_NUMBER))
    soc.send(bytes(BSP_JSON, 'utf-8'))
    msg = soc.recv(2048)
    soc.close()
    return json.loads(msg)

def enviar_resposta(bloco, book_key):
    return SOLVE_request(bloco, book_key)

print("Iniciando Mineração às {}".format(d.date.today()))
print("Insira a sua chave pública")
public_key = input()
print("Insira a sua chave privada")
private_key = input()
while (True):
    bloco, book_key = pegar_bloco()
    bloco_calculado = minerar_bloco(bloco)
    print(enviar_resposta(bloco_calculado, book_key))
    break # Remove Break ao funcionar