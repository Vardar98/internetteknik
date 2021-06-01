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
from Crypto.Cipher import PKCS1_v1_5
import numpy as np
import matplotlib.pyplot as plt
import datetime

   
class Solution(object):
   'Class Solution is taken from: https://www.tutorialspoint.com/number-of-1-bits-in-python'
   def hammingWeight(self, n):
      'Basicaly counts the 1s in a binary string'
      one_count = 0
      for i in n:
         if i == '1':
            one_count+=1
      return one_count

def xor(file1, file2, outfile):
   with open(file1,'r') as f1:
       text1 = f1.readlines()
   with open(file2,'r') as f2:
       text2 = f2.readlines()

   text1 = int(text1[0], 16)  # Translate the hexadecimal number to an integer in base 10, i.e. decimal number
   text2 = int(text2[0], 16)
   xored = text1 ^ text2      # XOR the two decimal numbers
   binary = bin(xored).replace("0b", "") # convert the decimal to binary
   with open(outfile,'w') as f3:
      f3.write(binary)  # Write the binary number to file f3

   all_count = 0 # Keeps track of all the bits in a file
   for i in bin(text1):
      all_count += 1  
   return binary, all_count


'''The following code is a little different version of the enc_dec_AES_DES_RSA.py. The following code
makes the encrypted value in hexadecimal which is not done in real enc_dec_AES_DES_RSA.py code. Furthermore,
here a constant key and iv is used so that only one bit in the whole system changes at a time.'''

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
    iv = '123456789abcdefg'
    encryptor = AES.new(key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8"))  # Define an encryptor
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0: #Makes the file divisible by 16.
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('ascii')
                outfile.write(binascii.hexlify(encryptor.encrypt(chunk)))  #Writes the encrypted code in hexadecimal format

def enc_dec_AES_CBC(number):
   key1 = 'emilemil12345678'
   if number == '0': # key should change 1 bit
      key2 = 'emildmil12345678'
   else: # plaintext should change
      key2 = key1
   encrypt_file_AES_CBC(key1, 'initial_text1.txt', 'text1.txt')
   encrypt_file_AES_CBC(key2, 'initial_text2.txt', 'text2.txt')
   binary, all_count = xor('text1.txt', 'text2.txt', 'xored.txt')
   ob1 = Solution()
   one_count = ob1.hammingWeight(binary)
   print('AVALANCHE EFFECT IN PERCENTAGE FOR AES_CBC mode is:', one_count/all_count*100)
   return

   

def encrypt_file_DES_CBC(key, in_filename, out_filename, chunksize=64*1024):
    iv = '12345678'    
    encryptor = DES.new(key.encode("utf8"), DES.MODE_CBC, iv.encode("utf8"))
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 8 != 0:
                    chunk += (' ' * (8 - len(chunk) % 8)).encode('ascii')
                outfile.write(binascii.hexlify(encryptor.encrypt(chunk)))

def enc_dec_DES_CBC(number):
   key1 = 'emilemil'
   if number == '0': # key should change 1 bit
      key2 = 'emildmil'
   else: # plaintext should change
      key2 = key1
   encrypt_file_DES_CBC(key1, 'initial_text1.txt', 'text1.txt')
   encrypt_file_DES_CBC(key2, 'initial_text2.txt', 'text2.txt')
   binary, all_count = xor('text1.txt', 'text2.txt', 'xored.txt')
   ob1 = Solution()
   one_count = ob1.hammingWeight(binary)
   print('AVALANCHE EFFECT IN PERCENTAGE FOR DES_CBC mode:', one_count/all_count*100)
   return


def key_generator_RSA():
    #Generate a public/ private key pair using 1024 bits key length (128 bytes)
    new_key = RSA.generate(1024)
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
   chunk_size = 86
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
            
       fd.write(binascii.hexlify(rsa_key.encrypt(chunk)))
       offset += chunk_size
   return rsa_key


def enc_RSA(file1, file2, public_key):
    fd = open(file1, "rb")
    unencrypted_blob = fd.read()
    fd.close()

    fd = open(file2, "wb")
    encrypt_RSA(unencrypted_blob, public_key, fd)
    fd.close()

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


def enc_dec_RSA(number):
   if number == '1':
      key_generator_RSA()
      public_key, private_key = obtain_priv_pub_key()
      enc_RSA('initial_text1.txt', 'text1.txt', public_key)
      enc_RSA('initial_text2.txt', 'text2.txt', public_key)
      binary, all_count = xor('text1.txt', 'text2.txt', 'xored.txt')
      ob1 = Solution()
      one_count = ob1.hammingWeight(binary)
      print('AVALANCHE EFFECT IN PERCENTAGE FOR RSA mode:', one_count/all_count*100)
   else:
      print('Since RSA is using random padding it does not make sense to change one bit in the RSA mode.')
   return

if __name__ == '__main__':
   while True:
      number = input('''If you want to change one bit in the plaintext write 1 (make sure that you have already changed 1 bit (or more if so wanted) in the text file manually). If you want to change 1 bit in the key write0 (make sure that the plaintexts are the same):''')
      if number == '0' or number == '1':
         break
   enc_dec_DES_CBC(number)
   enc_dec_AES_CBC(number)
   enc_dec_RSA(number)

