from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import datetime as d
import json
import socket as s
import base64
import hashlib as h

DIFICULDADE = 10
ALVO = 2 ** (256 - DIFICULDADE)
MAX_NONCE = 2 ** 32

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
    msg = soc.recv(4096)
    soc.close()
    return json.loads(msg)

def pegar_bloco():
    response = FETCH_request()
    if (response['response_code'] == 1):
        return False
    else:
        return response['block'], response['public_key']

def minerar_bloco(bloco):
    nonce = 0
    while (not(check_validity(nonce, bloco))):
        nonce += 1
    return nonce


def check_validity(nonce, block_to_solve):
    block_to_solve['mined_by'] = public_key
    block_to_solve['nonce'] = nonce
    hasher = h.sha256()

    if (nonce > MAX_NONCE):
        return False

    hasher.update(
        str(nonce).encode('utf-8') +
        str(block_to_solve['value']).encode('utf-8') +
        str(block_to_solve['last_hash']).encode('utf-8') +
        str(block_to_solve['datetime']).encode('utf-8') +
        str(block_to_solve['from']).encode('utf-8') +
        str(block_to_solve['to']).encode('utf-8') +
        str(block_to_solve['signature']).encode('utf-8') +
        str(block_to_solve['mined_by']).encode('utf-8') +
        str(block_to_solve['block_no']).encode('utf-8')
    )

    block_hash = hasher.hexdigest()
    if (int(block_hash, 16) <= ALVO):
        block_to_solve['hash'] = block_hash
        return True
    else:
        return False

def encrypt(msg, public_key):
    public_key = public_key.encode('utf-8')
    public_key = base64.b64decode(public_key)
    public_key_object = RSA.import_key(public_key)
    public_key_object = PKCS1_OAEP.new(public_key_object)
    crypt = public_key_object.encrypt(str(msg).encode('utf-8'))
    return crypt

def SOLVE_request(nonce, book_key):
    BSP = {}
    BSP['method'] = "SOLVE"
    BSP['from'] = public_key

    nonce_crypt = encrypt(nonce, book_key)
    nonce_crypt = base64.b64encode(nonce_crypt)
    nonce_crypt = nonce_crypt.decode('utf-8')

    BSP['nonce'] = nonce_crypt
    print(BSP)
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)

    soc = s.socket(s.AF_INET, s.SOCK_STREAM)

    soc.connect((IP_BOOK, PORT_NUMBER))
    soc.send(bytes(BSP_JSON, 'utf-8'))
    msg = soc.recv(4096)
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
    if (bloco != ''):
        bloco_calculado = minerar_bloco(bloco)
        print(enviar_resposta(bloco_calculado, book_key))
        print("Bloco Minerado às {}".format(d.date.today()))
