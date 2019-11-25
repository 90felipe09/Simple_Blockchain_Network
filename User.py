from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import datetime as d
import binascii as b
import socket as s
import json
import base64
import getpass

def generate_private_key():
    private_key = rsa.generate_private_key(public_exponent = 65537,
                                           key_size = 512,
                                           backend = default_backend())

    return private_key

def sign(message, key):
    signature = key.sign(message,
                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length = padding.PSS.MAX_LENGTH),
                         hashes.SHA256())
    print(signature)
    return signature

def check(message, public_key, signature):
    try:
        verification = public_key.verify(signature,
                          message,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256()
                          )
        return True
    except:
        return False

def criar_carteira():
    private_key = generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

PORT_NUMBER = 8080
IP_BOOK = 'localhost'

def LIST_request(carteira):
    BSP = {}
    BSP['method'] = "LIST"
    BSP['from'] = carteira
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)

    print(BSP_JSON)
    soc = s.socket(s.AF_INET, s.SOCK_STREAM)

    soc.connect((IP_BOOK, PORT_NUMBER))
    soc.send(bytes(BSP_JSON, 'utf-8'))
    msg = soc.recv(2048)
    soc.close()
    return json.loads(msg)

LIST = LIST_request('0')

print(LIST)

def calcular_saldo(LIST, carteira):
    blocos = LIST['blocks']
    saldo = 0
    for i in blocos:
        if(i['from'] == carteira):
            saldo -= float(i['value'])
        if(i['to'] == carteira):
            saldo += float(i['value'])
    return saldo

saldo = calcular_saldo(LIST, '0')
print(saldo)

private_key, carteira = criar_carteira()

print(carteira)
print(private_key)

def deserialize_key(private_key):
    deserialized_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption())

    return deserialized_key

deserialized_key = deserialize_key(private_key)
print(deserialized_key)

def load_private_key(deserialized_key):
    private_key = serialization.load_pem_private_key(
                                                 deserialized_key,
                                                 password=None,
                                                 backend=default_backend())

    return private_key

print(load_private_key(deserialized_key))

def deserialize_public_key(public_key):
    deserialized_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return deserialized_key

def load_public_key(deserialized_public_key):
    public_key = serialization.load_pem_public_key(deserialized_public_key, default_backend())
    return public_key

carteira = deserialize_public_key(carteira)
print(carteira)

print(load_public_key(carteira))

def SEND_request(bloco):
    BSP = {}
    BSP['method'] = "SEND"
    BSP['block'] = bloco
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)

    soc = s.socket(s.AF_INET, s.SOCK_STREAM)

    soc.connect((IP_BOOK, PORT_NUMBER))
    soc.send(bytes(BSP_JSON, 'utf-8'))
    msg = soc.recv(1024)
    soc.close()
    return json.loads(msg)

def pagar(valor, carteira, autor, key):
    print(key)
    key = key.encode('utf-8')
    print(key)
    key = base64.b64decode(key)
    key = load_private_key(key)
    bloco = {}
    bloco['datetime'] = str(d.date.today())
    bloco['value'] = str(valor)
    bloco['to'] = carteira#str(carteira)# mesmo para to
    bloco['from'] = autor#str(autor)
    block_to_sign = json.dumps(bloco,ensure_ascii=False).encode('utf-8')
    bloco['signature'] = (base64.b64encode(sign(block_to_sign, key))).decode('utf-8')
    return SEND_request(bloco)

#print(pagar(0,0,carteira,private_key))

while (True):
    try:
        print("Projeto de Redes de Computadores I - PCS 3614")
        print("\nComandos:")
        print("\tCriar Carteira")
        print("\tChecar Saldo <Carteira>")
        print("\tEnviar Dinheiro <Carteira Destino> <Carteira Fonte> <Valor (com .)>\n\tEnviar Dinheiro <Valor> <Destino> (Usa as credenciais da última carteira criada)")
        comando = input()
        if(comando == "Criar Carteira"):
            private_key, carteira = criar_carteira()
            deserialized_key = deserialize_key(private_key)
            deserialized_public_key = deserialize_public_key(carteira)
            print("Guarde esses valores:")
            print("Chave privada:")
            pv = base64.b64encode(deserialized_key).decode('utf-8')
            print(pv)
            print("Chave Pública")
            ch = base64.b64encode(deserialized_public_key).decode('utf-8')
            print(ch)

        if("Checar Saldo" in comando):
            carteira_alvo = comando.split(' ')[2]
            saldo = calcular_saldo(LIST_request(carteira_alvo),carteira_alvo)
            print("Saldo da Carteira:")
            print("{} Coins".format(saldo))

        if("Enviar Dinheiro" in comando):
            try:
                carteira_alvo = comando.split(' ')[2]
                carteira_fonte = comando.split(' ')[3]
                valor = comando.split(' ')[4]
                print("Inserir Chave Privada")
                senha = input()
                print(pagar(valor,carteira_alvo,carteira_fonte,senha))
            except:
                carteira_alvo = comando.split(' ')[3]
                carteira_fonte = ch
                valor = comando.split(' ')[2]
                senha = pv
                print(pagar(valor, carteira_alvo, carteira_fonte, senha))

    except:
        print("Comando Inválido")

