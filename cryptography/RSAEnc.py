from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import requests

#generate RSA keys 
print("generating RSA-4096 key pair")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
)
#save the priv key 
with open("private_key.pem", "wb") as priv_file:
    priv_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
#save the pub key
public_key = private_key.public_key()
with open("key.pub", "wb") as pub_file:
    pub_file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

print("public key saved as 'key.pub'.")
#create message file
message_content = "Matthew Fisher 2610526 4130Lab4"
with open("message.txt", "w") as msg_file:
    msg_file.write(message_content)

print("message saved as 'message.txt'.")
#sign message
print("signing message")
message_bytes = message_content.encode("ascii")
signature = private_key.sign(
    message_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)
#save signature
with open("signature.sig", "wb") as sig_file:
    sig_file.write(signature)

print("signature saved as 'signature.sig'.")

#encrypt message with pub key
print("downloading the public key")
response = requests.get("https://ayasinnur.com/uno4130/4130-PublicKey.pem")
if response.status_code == 200:
    class_public_key = serialization.load_pem_public_key(response.content)
    print("encrypting the message")
    ciphertext = class_public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    #save the encrypted message
    with open("message.encr", "wb") as enc_file:
        enc_file.write(ciphertext)

    print("encrypted message saved as 'message.encr'.")
else:
    exit(1)
print("all files have been created")
print("key.pub")
print("signature.sig")
print("message.encr")
print("message.txt")