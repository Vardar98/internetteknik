'''
A code by Emil Vardar. This code is generated as part of the course IK1552 Internetworking
given at Royal Institute of Technology (KTH), Stockholm, Sweden. The goal with the code is
analyze the differences between the symmetric key cryptographies: DES and AES, and asymmetric
key cryptography: RSA. The code caluclates the key derivation time for each cryptography
method. Furthermore, it calculates the encryption and decryption time for each cryptography
method. To make the differences clear it plots these times.

Feel free to use the code for any research. 
'''

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
import numpy as np
import matplotlib.pyplot as plt


TIMES = 1
# If there are more files then add them just here
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
            are more secure. In this work we have used a key
            with 16 bytes. 

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    iv = ''.join(chr(random.randint(0, 0x7F)) for i in range(16))   # Create a random iv which is 16 bytes long
    encryptor = AES.new(key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8")) # Define an encryptor
    filesize = os.path.getsize(in_filename) 

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv.encode("utf8"))    # Write the iv to the out file
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break # We are at the end of the code
                elif len(chunk) % 16 != 0: #Makes the file divisible by 16.
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('ascii') # We are padding necessary number of spaces to the end.
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
                    break # We have decrypted everything
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)


def key_generation():
    'This function is mainly to calculate the key derivation time for AES method.'
    key = ''.join(chr(random.randint(0, 0x7F)) for i in range(16))


def enc_dec_AES_CBC():
    time_key_AES = timeit.timeit(stmt=lambda: key_generation(), number=100000) # Calculate the key derivation time
    print('Key generation time for AES: ', time_key_AES/100000, 'seconds')
    key = ''.join(chr(random.randint(0, 0x7F)) for i in range(16))
    times_for_AES_CBC = []
    for i in range(len(INITIAL_FILES)):
        time1 = timeit.timeit(stmt=lambda: encrypt_file_AES_CBC(key,INITIAL_FILES[i],ENC_FILES[i]), number=TIMES)
        times_for_AES_CBC.append(time1)
        time2 = timeit.timeit(stmt=lambda: decrypt_file_AES_CBC(key, ENC_FILES[i], DEC_FILES[i]), number=TIMES)
        times_for_AES_CBC.append(time2)
    return times_for_AES_CBC # The AES will have the format: [enc_time_txt, dec_time_txt, enc_time_big_txt, dec_time_big_txt,...]


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
    iv = ''.join(chr(random.randint(0, 0x7F)) for i in range(8)) # Create a random iv that is 8 bytes long
    encryptor = DES.new(key.encode("utf8"), DES.MODE_CBC, iv.encode("utf8")) # Define an encryptor
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv.encode("utf8")) # Write the iv at the beginning of the output text
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 8 != 0:
                    chunk += (' ' * (8 - len(chunk) % 8)).encode('ascii')  # We are padding necessary number of spaces to the end so that the file becomes divisiable with 8
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


def key_generation_DES():
    'This function is mainly to calculate the key derivation time for DES method.'
    key = ''.join(chr(random.randint(0, 0x7F)) for i in range(8))


def enc_dec_DES_CBC():
    time_key_DES = timeit.timeit(stmt=lambda: key_generation(), number=100000)
    print('Key generation time for DES is: ', time_key_DES/100000, 'seconds')
    key = ''.join(chr(random.randint(0, 0x7F)) for i in range(8)) # Generate a random key that is 8 bytes long
    times_for_DES_CBC = []
    for i in range(len(INITIAL_FILES)):
        time1 = timeit.timeit(stmt=lambda: encrypt_file_DES_CBC(key,INITIAL_FILES[i],ENC_FILES[i]), number=TIMES)
        times_for_DES_CBC.append(time1)
        time2 = timeit.timeit(stmt=lambda: decrypt_file_DES_CBC(key, ENC_FILES[i], DEC_FILES[i]), number=TIMES)
        times_for_DES_CBC.append(time2)
    return times_for_DES_CBC


def key_generator_RSA():
    start = time.time()
    #Generate a public/ private key pair using 1024 bits key length (128 bytes)
    new_key = RSA.generate(1024)
    end = time.time()
    key_time = end-start
    print('Key generation time for RSA process is: ', key_time, 'seconds') # The key generation time for RSA process 
    
    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")
    #The private key in PEM format
    private_key = new_key.exportKey("PEM")

    fd = open("private_key.pem", "wb") # Write the private key to a file named private_key.pem
    fd.write(private_key)
    fd.close()

    fd = open("public_key.pem", "wb") # Write the private key to a file named public_key.pem
    fd.write(public_key)
    fd.close()



def encrypt_RSA(blob, public_key, fd):
    #Import the Public Key and use for encryption using PKCS1_OAEP. PKCS1_OAEP uses random padding. 
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #In determining the chunk size, determine the private key length used in bytes in our case this is 128 bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). So in our case this is 128-42=86. The data will be in encrypted
    #in chunks
    chunk_size = 86
    offset = 0
    end_loop = False
    encrypted =  ""

    while not end_loop:
        #The chunk
        chunk = blob[offset:offset + chunk_size] # Take a chunk that is chunk_size big

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates that we reached the end of the file
        #so we end loop here.
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
    chunk_size = 128
    offset = 0

    #keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        #Base 64 decode the data
        chunk = (encrypted_blob[offset: offset + chunk_size])
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
    encrypt_RSA(unencrypted_blob, public_key, fd) # Writes the encyrpted text in the fd file
    fd.close()

def dec_RSA(file1, file2, private_key):
    fd = open(file1, "rb")
    encrypted_blob = fd.read()
    fd.close()

    fd = open(file2, "wb")
    decrypt_RSA(encrypted_blob, private_key, fd) # Writes the decrypted text in the fd file
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
    return times_for_RSA


def plot_graph_enc(aes_list, des_list, rsa_list):     
    # set width of bar
    barWidth = 0.25
    fig = plt.subplots(figsize =(12, 8))

    AES_ENC = []
    DES_ENC = []
    RSA_ENC = []

    # set height of bar
    for i in range(int(len(aes_list)/2)):
        AES_ENC.append(aes_list[2*i])
        DES_ENC.append(des_list[2*i])
        RSA_ENC.append(rsa_list[2*i])      
     
    # Set position of bar on X axis
    br1 = np.arange(len(AES_ENC))
    br2 = [x + barWidth for x in br1]
    br3 = [x + barWidth for x in br2]
     
    # Make the plot
    plt.bar(br1, AES_ENC, color ='r', width = barWidth,
            edgecolor ='grey', label ='t_{AES_ENC}')
    plt.bar(br2, DES_ENC, color ='g', width = barWidth,
            edgecolor ='grey', label ='t_{DES_ENC}')
    plt.bar(br3, RSA_ENC, color ='b', width = barWidth,
            edgecolor ='grey', label ='t_{RSA_ENC}')
     
    # Adding Xticks
    plt.xlabel('Different file formats and sizes', fontweight ='bold', fontsize = 30)
    plt.ylabel('Time in seconds', fontweight ='bold', fontsize = 30)
    plt.xticks([r + barWidth for r in range(len(AES_ENC))],
            ['txt-595', 'txt-1189', 'png-519', 'png-1188', 'pdf-583', 'pdf-1189'], fontsize = 20)
    plt.yticks(fontsize = 20)
    #plt.legend()
    plt.legend(prop={'size': 20})
    plt.show()


def plot_graph_dec(aes_list, des_list, rsa_list):     
    # set width of bar
    barWidth = 0.25
    fig = plt.subplots(figsize =(12, 8))


    AES_DEC = []
    DES_DEC = []
    RSA_DEC = []

    # set height of bar
    for i in range(int(len(aes_list)/2)):
        AES_DEC.append(aes_list[2*i+1])
        DES_DEC.append(des_list[2*i+1])
        RSA_DEC.append(rsa_list[2*i+1])  
    
    # Set position of bar on X axis
    br1 = np.arange(len(AES_DEC))
    br2 = [x + barWidth for x in br1]
    br3 = [x + barWidth for x in br2]
     
    # Make the plot
    plt.bar(br1, AES_DEC, color ='r', width = barWidth,
            edgecolor ='grey', label ='t_{AES_DEC}')
    plt.bar(br2, DES_DEC, color ='g', width = barWidth,
            edgecolor ='grey', label ='t_{DES_DEC}')
    plt.bar(br3, RSA_DEC, color ='b', width = barWidth,
            edgecolor ='grey', label ='t_{RSA_DEC}')
     
    # Adding Xticks
    plt.xlabel('Different file formats and sizes', fontweight ='bold', fontsize = 30)
    plt.ylabel('Time in seconds', fontweight ='bold', fontsize = 30)
    plt.xticks([r + barWidth for r in range(len(AES_DEC))],
            ['txt-595', 'txt-1189', 'png-519', 'png-1188', 'pdf-583', 'pdf-1189'], fontsize = 20)
    plt.yticks(fontsize = 20)
    plt.legend(prop={'size': 20})
    plt.show()

        

if __name__ == '__main__':
    aes_list = enc_dec_AES_CBC()
    des_list = enc_dec_DES_CBC()
    rsa_list = enc_dec_RSA()
    plot_graph_enc(aes_list, des_list, rsa_list)
    plot_graph_dec(aes_list, des_list, rsa_list)
    rsa2_list = []
    for i in range(2*len(INITIAL_FILES)):
        rsa2_list.append(0)
    plot_graph_enc(aes_list, des_list, rsa2_list)
    plot_graph_dec(aes_list, des_list, rsa2_list)
