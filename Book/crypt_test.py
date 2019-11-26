from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import base64

def encrypt(msg, public_key):
    public_key = public_key.encode('utf-8')
    public_key = base64.b64decode(public_key)
    public_key_object = RSA.import_key(public_key)
    public_key_object = PKCS1_OAEP.new(public_key_object)
    crypt = public_key_object.encrypt(msg)
    return crypt

def decrypt (crypt, private_key):
    private_key = private_key.encode('utf-8')
    private_key = base64.b64decode(private_key)
    private_key_object = RSA.import_key(private_key)
    private_key_object = PKCS1_OAEP.new(private_key_object)
    msg = private_key_object.decrypt(crypt)
    return msg

private_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUJVd0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQVQwd2dnRTVBZ0VBQWtFQXVLb1J4NHRLYzJzR0FnQ3kKWE9DNXRpRGs1NFZUMEZwaCt4anFrZlVvQXEyV0JYbWUzWGkvQTZYVGJ0MzFXaFNUdU5HOG82OS9WMk50YWxhcgpNcXluS3dJREFRQUJBa0I2aXRGVm04ZUNKQWxPbHV2RjJwTWltMTJMamR4NnJSL01JMUsySFB1NkdoajBJUWk5CkdvSEU2TVNUVDBiSkR4dzZkRC83ZSt3eEhiVjVtczAwUDZpeEFpRUE4Z0F1ZzlZMFpsOWZuM1VtYjVrUnQ1UDIKeTRZd2NQQ3Nva05NWThCZ2RyOENJUUREV01sTEdKUFV5aDdsaUY1NDZHZFZXUVNPWTlEaEYrSkJYaENQbnBUMgpsUUlnTUgydzFHSDdwZmUrWldsSUJseVpuRHRkM0hKTENwWnZRU1JURGpuaUdta0NJQjlDT3R1NGNCZHh6R1hnClgzV3JncldHakJNWTU5ak5FSmh6SytVL2RBak5BaUE1SmdUSFE2WWp4ckVzK0JxVFhOLzFDemhEWXhvamtYcHAKcVBITWVXdmhJUT09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"
public_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTGlxRWNlTFNuTnJCZ0lBc2x6Z3ViWWc1T2VGVTlCYQpZZnNZNnBIMUtBS3RsZ1Y1bnQxNHZ3T2wwMjdkOVZvVWs3alJ2S092ZjFkamJXcFdxektzcHlzQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="

def load_private_key(deserialized_key):
    private_key = serialization.load_pem_private_key(
                                                 deserialized_key,
                                                 password=None,
                                                 backend=default_backend())

    return private_key

def load_public_key(deserialized_public_key):
    public_key = serialization.load_pem_public_key(deserialized_public_key, default_backend())
    return public_key

pbk = public_key.encode('utf-8')
pbk = base64.b64decode(pbk)
#pbk = load_public_key(pbk)
print(pbk)

pvk = private_key.encode('utf-8')
pvk = base64.b64decode(pvk)
#pvk = load_private_key(pvk)
print(pvk)

msg = b"3389"

crypt = encrypt(msg, pbk)
print(crypt)

msg = decrypt(crypt, pvk)
print(msg)





