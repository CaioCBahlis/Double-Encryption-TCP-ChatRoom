import socket
import threading
import EncryptMe
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

Nickname = str(input("What is your Nickname?"))


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 65511))

def EncryptME(message):
    cipher = AES.new(Aes_Key, AES.MODE_EAX)
    message, tag = cipher.encrypt_and_digest(message)
    nonce = cipher.nonce
    #print(f'{type(cipher), type(message), type(nonce)}')
    AESPAYLOAD = tag+nonce+bytes(message)
    return AESPAYLOAD
def receive():
    while True:
        try:
            message = client.recv(1024).decode("ascii")
            if message == "NICK":
                client.send(Nickname.encode("ascii"))
            else:
                print(message)
        except:
            print("An Error Ocurred")
            client.close()
            break

def write():
    while True:
        message = f"{Nickname}: {input()}"
        print(message)
        Encmessage = EncryptME(message.encode("utf-8"))
        #print(Encmessage)
        client.send(Encmessage)

def RSASetup():
    Serialized_Sv_PublicKey = client.recv(4096)
    SV_Public_Key = RSA.import_key(Serialized_Sv_PublicKey)
    print(f"Server Serialized PKey: {Serialized_Sv_PublicKey} and not Serialized {SV_Public_Key}  ")
    key = RSA.generate(2048)
    Mypublic_key = key.publickey().export_key()
    Myprivkeythatalsoshouldbeinafile = key.export_key()
    try:
        client.send(Mypublic_key)
        print("Public Key Encryption Has Been Established")
    except:
        print("Encryption has failed")
        print("Trying Again...")
        client.close()
        RSASetup()

    
    AES_KEY = AESSetup(key)

    return AES_KEY

def AESSetup(key):
    AESKey = client.recv(2048)
    

    countercipher = PKCS1_OAEP.new(key)
    AESKey = countercipher.decrypt(AESKey)


    return AESKey


Aes_Key = RSASetup()


rcvthread = threading.Thread(target=receive)
writethread = threading.Thread(target=write)

rcvthread.start()
writethread.start()
