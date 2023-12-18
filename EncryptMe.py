from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
alphabet = "abcdefghijklmnopqrstuvwxyz"


def CesarMe(plaintext,par):
    newtext = ""
    plaintext = plaintext.lower()

    for i in plaintext:
        print(newtext)
        if i not in alphabet:
            newtext += i
        else:
            newtext += alphabet[(((alphabet.index(i))+par)%26)]

    return newtext

def VigenereMe(text,key, Mode):
    newtext = ""
    text  = text.lower()
    values = [alphabet.index(i.lower()) for i in key]

    if Mode == 0 or Mode == 1:
        sign = 1 if Mode == 0 else -1
        for i in text:
            if i not in alphabet:
                newtext += i
            else:
                newtext += alphabet[(alphabet.index(i) + sign*values[text.index(i)]) % 26]
        return newtext
    else:
        raise ValueError("Mode Is Invalid")

def BaconMe(Plaintext, Mode):
    Newtext = ""
    bacon_cipher = {
        'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
        'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
        'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
        'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
        'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
        'Z': 'BBAAB'
    }

    decrypt_bacon_cipher = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
        'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
        'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
        'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
        'BBAAB': 'Z'
    }

    if Mode == 0: # Encode
        Newtext = "".join([bacon_cipher[i.upper()] for i in Plaintext])
        return Newtext
    elif Mode == 1:#Decode
        Decode = "".join([decrypt_bacon_cipher[Plaintext[i:i+5].upper()] for i in range(0, len(Plaintext),5)])
        return Decode
    else:
        return ValueError("Mode is Invalid")

#Random_AES_key = get_random_bytes(AES.block_size)
# Using #Random_AES_key = get_random_bytes(AES.block_size) because I don't have a key
# 1 Parameter is Key, 2 parameter is the message (encrypted or decrypted)

def encrypt_aes(plaintext):
    key = get_random_bytes(AES.block_size)
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext = iv + ciphertext
    return [key, ciphertext]

def decrypt_aes(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return decrypted_data


def Get_Prime():

    while True:
        num = random.randint(1000,10000)
        for i in range(1000,int(num/2),1):
            if num % i == 0:
                break
        return num






