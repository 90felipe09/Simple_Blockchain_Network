"""
Felipe Kenzo Shiraishi - 10262700
Tiago Santa Maria R. Marto - 9004289
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import socket as s
import threading as t
import datetime as d
import os
import csv
import json
import base64

book_path_to_solve = "to_solve.csv"
book_path_solved = "solved.csv"

# Crypt Methods
def deserialize_key(private_key):
    deserialized_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption())

    return deserialized_key


def generate_private_key():
    private_key = rsa.generate_private_key(public_exponent = 65537,
                                           key_size = 512,
                                           backend = default_backend())

    return private_key

def criar_carteira():
    private_key = generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = criar_carteira()

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

def load_public_key(deserialized_public_key):
    public_key = serialization.load_pem_public_key(deserialized_public_key, default_backend())
    return public_key

def deserialize_public_key(public_key):
    deserialized_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return deserialized_key

# TEST
def decrypt(msg):
    result = private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return result

#Work
def create_book():
    files = os.listdir('.')

    if (book_path_to_solve not in files):
        header_to_solve = "block_no;datetime;from;to;value;last_hash;signature\n"

        with open(book_path_to_solve, 'w', encoding="utf8") as w:
            w.write(header_to_solve)

    if (book_path_solved not in files):
        header_solved = "block_no;datetime;from;to;value;last_hash;block_hash;signature;nonce\n"
        today = str(d.date.today())
        first_element = "0;{};0;0;0;0;0;0;0\n".format(today)
        header_solved += first_element
        with open(book_path_solved, 'w', encoding="utf8") as w:
            w.write(header_solved)

create_book()

def insert_to_solve(block):
    with open(book_path_solved, 'r', encoding="utf8") as r:
        csv_reader = csv.DictReader(r, delimiter=';')
        last_entry = ""
        for i in csv_reader:
            last_entry = i
        blockno = last_entry['block_no']
        lastHash = last_entry['block_hash']
    entry = (
            blockno + ";" +
            block['datetime'] + ";" +
            block['from'] + ";" +
            block['to'] + ";" +
            block['value'] + ";" +
            lastHash + ";" +
            block['signature']  +
            '\n'
    )
    print(entry)
    with open(book_path_to_solve, 'a', encoding="utf8") as w:
        w.write(entry)

block = {}
block['datetime'] = str(d.date.today())
block['from'] = "asdasd"
block['to'] = "asdasd"
block['value'] = "asdasd"
block['signature'] = "asdasd"

#Data Manipulation
def delete_to_solve():
    infile = open(book_path_to_solve, 'r').readlines()
    with open(book_path_to_solve, 'w') as outfile:
        for index, line in enumerate(infile):
            if index != 1:
                outfile.write(line)

def get_block_to_solve():
    with open(book_path_to_solve, 'r', encoding="utf8") as r:
        block_to_solve_raw = r.readline()
        block_to_solve_raw = r.readline()
        block_to_solve_raw = block_to_solve_raw.split(';')
        block_to_solve = {}
        block_to_solve['block_no'] = block_to_solve_raw[0]
        block_to_solve['datetime'] = block_to_solve_raw[0]
        block_to_solve['from'] = block_to_solve_raw[0]
        block_to_solve['to'] = block_to_solve_raw[0]
        block_to_solve['value'] = block_to_solve_raw[0]
        block_to_solve['last_hash'] = block_to_solve_raw[0]
        block_to_solve['signature'] = block_to_solve_raw[0]
        return block_to_solve

def list_blocks_solved(user):
    blocks = []
    with open(book_path_solved, 'r', encoding="utf8") as r:
        csv_reader = csv.DictReader(r, delimiter=';')
        for i in csv_reader:
            if (i['from'] == user or i['to'] == user):
                block_solved = {}
                block_solved['block_no'] = i['block_no']
                block_solved['datetime'] = i['datetime']
                block_solved['from'] = i['from']
                block_solved['to'] = i['to']
                block_solved['value'] = i['value']
                block_solved['last_hash'] = i['last_hash']
                block_solved['block_hash'] = i['block_hash']
                block_solved['signature'] = i['signature']
                block_solved['nonce'] = i['nonce']
                blocks.append(block_solved)
    return blocks

def insert_solved(block):
    entry = (
            block['block_no'] + ";" +
            block['datetime'] + ";" +
            block['from'] + ";" +
            block['to'] + ";" +
            block['value'] + ";" +
            block['last_hash'] + ";" +
            block['block_hash'] + ";" +
            block['signature'] + ";" +
            block['nonce'] +
            '\n'
    )
    with open(book_path_solved, 'a', encoding="utf8") as w:
        w.write(entry)


#Response Methods
def response_LIST(response_code, blocks):
    BSP = {}
    BSP['response_code'] = response_code
    BSP['blocks'] = blocks
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)
    return BSP_JSON

def response_SEND(response_code):
    BSP = {}
    BSP['response_code'] = response_code
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)
    return BSP_JSON

# TEST
def response_FETCH(response_code):
    BSP = {}
    BSP['response_code'] = response_code
    BSP['block'] = get_block_to_solve()
    deserialized_public_key = deserialize_public_key(public_key)
    ch = base64.b64encode(deserialized_public_key).decode('utf-8')
    BSP['public_key'] = ch
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)
    return BSP_JSON

# TEST
def response_SOLVE(response_code):
    BSP = {}
    BSP['response_code'] = response_code
    BSP_JSON = json.dumps(BSP, ensure_ascii=False)
    return BSP_JSON


#Compliance Methods
def check_authenticity(block):
    block_to_check = {}
    block_to_check['datetime'] = block['datetime']
    block_to_check['value'] = block['value']
    block_to_check['to'] = block['to']
    block_to_check['from'] = block['from']
    block_to_check = json.dumps(block_to_check, ensure_ascii=False).encode('utf-8')
    signature = block['signature'].encode('utf-8')
    signature = base64.b64decode(signature)
    public_key = block['from']
    public_key = public_key.encode('utf-8')
    public_key = base64.b64decode(public_key)
    loaded_public_key = load_public_key(public_key)
    return (check(block_to_check,loaded_public_key,signature))

# TEST
def check_validity(nonce):
    print(1)

# TEST
def premiar_minerador(nonce, minerador):
    print(2)

soc = s.socket(s.AF_INET, s.SOCK_STREAM)

PORT_NUMBER = 8080

soc.bind(('localhost', PORT_NUMBER))
def thread_socket(clSocket):
    msg = clSocket.recv(2048).decode('utf-8')
    message = json.loads(msg)
    msg_method = message['method']
    if (msg_method == "LIST"):
        user = message["from"]
        blocks_list = list_blocks_solved(user)
        try:
            BSP_JSON = response_LIST(0, blocks_list)
        except:
            BSP_JSON = response_LIST(1, "")
        print(0)
    # TEST
    if (msg_method == "SOLVE"):
        print(1)
        nonce = decrypt(message['nonce'])
        if(check_validity(nonce)):
            premiar_minerador(nonce, message['from'])
            BSP_JSON = response_SOLVE(0)
        else:
            BSP_JSON = response_SOLVE(0)
    if (msg_method == "SEND"):
        print(2)
        bloco = message["block"]
        try:
            if (check_authenticity(bloco)):
                insert_to_solve(bloco)
                BSP_JSON = response_SEND(0)
            else:
                BSP_JSON = response_SEND(1)
        except:
            BSP_JSON = response_SEND(1)
    # TEST
    if (msg_method == "FETCH"):
        print(3)
        try:
            BSP_JSON = response_FETCH(0)
        except:
            BSP_JSON = response_FETCH(1)

    clSocket.send(bytes(BSP_JSON, "utf-8"))
    clSocket.close()
    
while(True):
    soc.listen(1)
    (clientsocket, address) = soc.accept()
    thread = t.Thread(target=thread_socket,args=(clientsocket,))
    thread.start()
