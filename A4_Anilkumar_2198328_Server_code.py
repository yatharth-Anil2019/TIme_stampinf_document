import socket
import datetime
import random
import gmpy2
from gmpy2 import *
import time
from time import gmtime, strftime
import hashlib


class RSA:

	e= -1
	d= -1
	listType= [] # For detecting whether the character at that position is an alphabet or a digit
	listValues= [] # For detecting whether that character value is in single digit or double for eg. if 'a'=1 than 'j'=10 we have to decode in that way

	def __init__(self, p, q):
		self.p= p
		self.q= q
		self.phi= (p-1)*(q-1)
		self.n= p*q
		self.listType= []
		self.listValues= []

	
	def isPrime(self, val):
		if(val== 1):
			return False
		i= 2;
		while(i*i <= val):
			if(val%i== 0):
				return False
			i+=1;
		return True


	def calc_e(self):
		while(True):
			num= random.randint(self.q+1, self.phi-1)
			if(self.isPrime(num)):
				return num
		return 2


	def euclid(self, e, phi, q_list, r_list):
		if(e== 0):
			return q_list, r_list, self.phi
		q_list.append(phi//e)
		r_list.append(phi%e)
		return self.euclid(phi%e, e, q_list, r_list) 


	def calc_values(self):
		q_list= [0,0]
		r_list= [0,0]
		self.e= self.calc_e()
		return self.euclid(self.e, self.phi, q_list, r_list)


	def calc_d(self):
		d_list= [0,1]
		q_list, r_list, phi= self.calc_values()
		for i in range(2, len(q_list)):
			d_list.append(d_list[i-2]-q_list[i] * d_list[i-1])
		return mpz(self.e), mpz(d_list[len(d_list)-2]), mpz(self.n), mpz(self.phi)


	def generate_keys(self):
		while(True):
			e,d,n,phi= self.calc_d()
			if(d>0):
				break;
		return e,d,n,phi


	def count_digits(self, num):
		if(num== 0):
			return 1
		count= 0
		while(num> 0):
			count= count+1
			num= num//10
		return count


	def generate_cipher_text(self, msg, e, n):
		e= mpz(e)
		n= mpz(n)
		cipher_msg= ''
		for i in msg:
			asci= ord(i)
			val= 0
			_type= ''
			if(i.isalpha()):
				if(i.isupper()):
					val= asci- 65;
					_type= 'u'
				else:
					val= asci- 97;
					_type= 'l'
			elif(i.isdigit()):
				val= asci- 48;
				_type= 'd'
			else:
				val= asci;
				_type= 'o'
			self.listType.append(_type)
			val= mpz(powmod(val, e, n))
			cipher_msg= cipher_msg+str(val)
			dig= self.count_digits(int(val))
			self.listValues.append(dig)
		return cipher_msg


	def decipher_ciphered_text(self, enc_text, d, n, listType, listValues):
		d= mpz(d)
		n= mpz(n)
		decipher_text= ''
		for i in range(0, len(listValues)):
			index= int(listValues[i])
			val= mpz(enc_text[0:index])
			enc_text= enc_text[index:]
			dec_part= int(mpz(powmod(val, d, n)))
			if(listType[i]=='u'):
				dec_part= dec_part+65
			elif(listType[i]=='l'):
				dec_part= dec_part+97
			elif(listType[i]=='d'):
				dec_part= dec_part+48
			elif(listType[i]=='o'):
				dec_part= dec_part
			dec_part= str(chr(dec_part))
			decipher_text= decipher_text+ dec_part
		return decipher_text


def generate_hash(msg):
	hash_val= hashlib.sha256(msg.encode()).hexdigest()
	return hash_val


def gen_formatted_text(msg):
	index1= -1
	index2= -1
	index3= -1
	for i in range(0, len(msg)):
		if(msg[i]==','):
			if(index1== -1):
				index1= i
			elif(index2== -1):
				index2= i
			else:
				index3= i
				break
	val1= msg[0: index1]
	val2= msg[index1+1: index2]
	val3= list(msg[index2+1: index3])
	val4= list(msg[index3+1:])
	return val1, val2, val3, val4


def generate_encrypt_value(Type, value, hash_val, key, n):
	encrypt_val= Type.generate_cipher_text(value, key, n)
	print("Digital Sign Generated:", encrypt_val)
	listVal= ''
	listType= ''
	for i in range(0, len(Type.listType)):
		listVal= listVal+str(Type.listValues[i])
		listType= listType+str(Type.listType[i])
	encrypt_val= encrypt_val+","+hash_val+","+listType+","+listVal
	return encrypt_val


port_num= 9999


Server= RSA(17, 37)
e,d,n,phi= Server.generate_keys()
print(e,d)

server= socket.socket()
print("Socket created")

server.bind(('localhost',port_num))
server.listen(1)
print("Waiting for connection....")

while(True):
	client, addr= server.accept()
	print('Connected')

	msg= str(e)+","+str(n)
	client.send(bytes(msg,'utf-8'))
	encrypted_hash_value= client.recv(1024).decode()
	cipher_txt, hash_val, listType, listVal= gen_formatted_text(encrypted_hash_value)
	decrypt_text= Server.decipher_ciphered_text(cipher_txt, d, n, listType, listVal)
	
	if(decrypt_text== hash_val):
		print("Msg has not been tampered")
		print("Hash Val Find:", decrypt_text)
		gmt_val= time.strftime("%d %b %Y %I:%M:%S %p", time.gmtime())
		hash_hash_val= generate_hash(hash_val) + str(gmt_val)
		encrypt_val= generate_encrypt_value(Server, hash_hash_val, hash_hash_val, d, n)
		client.send(str(len(encrypt_val)).encode())
		client.send(bytes(encrypt_val,'utf-8'))

	else:
		print("Msg has been tampered")

	client.close()
	break