import os
import random
import struct
import binascii
import timeit
import time
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


TIMES = 1
INITIAL_FILES = ['initial_text.txt', 'initial_big_text.txt','initial_pic.png', 'initial_big_pic.png', 'initial_file.pdf' , 'initial_big_file.pdf']
ENC_FILES = ['enc_text.txt', 'enc_big_text.txt','enc_pic.png', 'enc_big_pic.png', 'enc_file.pdf', 'enc_big_file.pdf']
DEC_FILES =['dec_text.txt', 'dec_big_text.txt','dec_pic.png', 'dec_big_pic.png','dec_file.pdf', 'dec_big_file.pdf'] 




'''FOR THE CODE BELOW CODES IN: https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
AND https://ismailakkila.medium.com/black-hat-python-encrypt-and-decrypt-with-rsa-cryptography-bd6df84d65bc HAS BEEN VERY HELPFUL'''
def encrypt_file_AES_CBC(key, in_filename, out_filename, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    iv = ''.join(chr(random.randint(0, 0x7F)) for i in range(16))
    encryptor = AES.new(key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8"))
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv.encode("utf8"))
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0: #Makes the file divisible by 16.
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('ascii')
                #outfile.write(binascii.hexlify(encryptor.encrypt(chunk)))  #Writes the encrypted code in hexadecimal format
                outfile.write(encryptor.encrypt(chunk))

def decrypt_file_AES_CBC(key, in_filename, out_filename, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key.
    """
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key.encode("utf8"), AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)

def enc_dec_AES_CBC():
    start = time.time()
    key = ''.join(chr(random.randint(0, 0x7F)) for i in range(16))
    end = time.time()
    key_time = end-start
    times_for_AES_CBC = []
    for i in range(len(INITIAL_FILES)):
        time1 = timeit.timeit(stmt=lambda: encrypt_file_AES_CBC(key,INITIAL_FILES[i],ENC_FILES[i]), number=TIMES)
        times_for_AES_CBC.append(time1+key_time)
        time2 = timeit.timeit(stmt=lambda: decrypt_file_AES_CBC(key, ENC_FILES[i], DEC_FILES[i]), number=TIMES)
        times_for_AES_CBC.append(time2)
    #encrypt_file_AES_CBC(key,'initial_pic.png','enc_pic.png')
    #decrypt_file_AES_CBC(key, 'enc_pic.png', 'dec_pic.png')
    #encrypt_file_AES_CBC(key,'initial_text.txt','enc_text.txt')
    #decrypt_file_AES_CBC(key, 'enc_text.txt', 'dec_text.txt')
    #encrypt_file_AES_CBC(key,'initial_file.pdf','enc_file.pdf')
    #decrypt_file_AES_CBC(key, 'enc_file.pdf', 'dec_file.pdf')
    return times_for_AES_CBC

def encrypt_file_DES_CBC(key, in_filename, out_filename, chunksize=64*1024):
    """ Encrypts a file using DES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            8 bytes long.
            
        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 8.
    """
        
    iv = '12345678'    
    encryptor = DES.new(key.encode("utf8"), DES.MODE_CBC, iv.encode("utf8"))
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv.encode("utf8"))
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 8 != 0:
                    chunk += (' ' * (8 - len(chunk) % 8)).encode('ascii')
                outfile.write(encryptor.encrypt(chunk))

def decrypt_file_DES_CBC(key, in_filename, out_filename, chunksize=24*1024):
    """ Decrypts a file using DES (CBC mode) with the
        given key.
    """

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(8)
        decryptor = DES.new(key.encode("utf8"), DES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)


def enc_dec_DES_CBC():
    start = time.time()
    key = ''.join(chr(random.randint(0, 0x7F)) for i in range(8))
    end = time.time()
    key_time = end-start
    times_for_DES_CBC = []
    for i in range(len(INITIAL_FILES)):
        time1 = timeit.timeit(stmt=lambda: encrypt_file_DES_CBC(key,INITIAL_FILES[i],ENC_FILES[i]), number=TIMES)
        times_for_DES_CBC.append(time1 + key_time)
        time2 = timeit.timeit(stmt=lambda: decrypt_file_DES_CBC(key, ENC_FILES[i], DEC_FILES[i]), number=TIMES)
        times_for_DES_CBC.append(time2)
    '''
    encrypt_file_DES_CBC(key,'initial_pic.png','enc_pic.png')
    decrypt_file_DES_CBC(key, 'enc_pic.png', 'dec_pic.png')
    encrypt_file_DES_CBC(key,'initial_text.txt','enc_text.txt')
    decrypt_file_DES_CBC(key, 'enc_text.txt', 'dec_text.txt')
    encrypt_file_DES_CBC(key,'initial_file.pdf','enc_file.pdf')
    decrypt_file_DES_CBC(key, 'enc_file.pdf', 'dec_file.pdf')
    '''
    return times_for_DES_CBC


def key_generator_RSA():
    #Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=3)

    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")


    #The private key in PEM format
    private_key = new_key.exportKey("PEM")
    
    #print(private_key)
    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    #print(public_key)
    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()



def encrypt_RSA(blob, public_key, fd):
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    #in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  ""

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file
        #so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += (' ' * (chunk_size - len(chunk))).encode('ascii')

        #Encrypt using RSA
        fd.write(rsa_key.encrypt(chunk))
        #Increase the offset by chunk size
        offset += chunk_size


def decrypt_RSA(encrypted_blob, private_key, fd):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #In determining the chunk size, determine the private key length used in bytes.
    #The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #Base 64 decode the data
        chunk = (encrypted_blob[offset: offset + chunk_size])
        #The chunk
        #chunk = encrypted_blob[offset: offset + chunk_size]

        #Decrypt the chunk and write on the file
        fd.write(rsakey.decrypt(chunk))

        #Increase the offset by chunk size
        offset += chunk_size
    return


def obtain_priv_pub_key():
    #Use the public key for encryption
    fd = open("public_key.pem", "rb")
    public_key = fd.read()
    fd.close()

    #Use the private key for decryption
    fd = open("private_key.pem", "rb")
    private_key = fd.read()
    fd.close()
    return public_key, private_key


def enc_RSA(file1, file2, public_key):
    fd = open(file1, "rb")
    unencrypted_blob = fd.read()
    fd.close()

    fd = open(file2, "wb")
    encrypt_RSA(unencrypted_blob, public_key, fd)
    fd.close()

def dec_RSA(file1, file2, private_key):
    fd = open(file1, "rb")
    encrypted_blob = fd.read()
    fd.close()

    fd = open(file2, "wb")
    decrypt_RSA(encrypted_blob, private_key, fd)
    fd.close()


def enc_dec_RSA():
    key_generator_RSA()
    public_key, private_key = obtain_priv_pub_key()
    times_for_RSA = []
    for i in range(len(INITIAL_FILES)):
        time1 = timeit.timeit(stmt=lambda: enc_RSA(INITIAL_FILES[i],ENC_FILES[i], public_key), number=TIMES)
        times_for_RSA.append(time1)
        time2 = timeit.timeit(stmt=lambda: dec_RSA(ENC_FILES[i], DEC_FILES[i], private_key), number=TIMES)
        times_for_RSA.append(time2)
    '''
    enc_RSA('initial_pic.png','enc_pic.png', public_key)
    dec_RSA('enc_pic.png', 'dec_pic.png', private_key)
    enc_RSA('initial_text.txt','enc_text.txt', public_key)
    dec_RSA('enc_text.txt', 'dec_text.txt', private_key)
    enc_RSA('initial_file.pdf','enc_file.pdf', public_key)
    dec_RSA('enc_file.pdf', 'dec_file.pdf', private_key)
    '''
    return times_for_RSA

if __name__ == '__main__':
    list1 = enc_dec_AES_CBC()
    print(list1)
    #list2 = enc_dec_DES_CBC()
    #print(list2)
    #list3 = enc_dec_RSA()
    #print(list3)

