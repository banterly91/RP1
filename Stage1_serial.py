import sys
from struct import *
import datetime
def locateData(f,plaintext):
	file_name=""	
	while (1):
		while( f.read(1)!="P"):
			pass

		sig=[ord(f.read(1)) for x in range(3)]		
		file_header_sig=int(("{0}{1}{2}".format(sig[0],sig[1],sig[2])))		
		
		if(file_header_sig==7534):
			f.seek(14,1)		
			file_size=unpack('I',f.read(4))[0]		
			f.seek(4,1)
			name_length=unpack('H',f.read(2))[0]
			if(name_length!=len(plaintext)):
				continue
			else:				
				extra_field_length=unpack('H',f.read(2))[0]		
				#print extra_field_length 	
				#print name_length	
				file_name=unpack(str(name_length)+'s',f.read(name_length))[0]
				
				if(file_name==plaintext):
					f.seek(extra_field_length,1)
					return file_size,f.tell()				
				else:
					continue					
		else:
			continue



def crc32(temp1, i):
	temp1=temp1 ^ i
	for j in xrange(8):
		if not temp1%2==0:
			temp1=(temp1 >> 1) ^ 0xEDB88320
		else:
			temp1=temp1 >> 1
		
	return temp1


def init_crc():
	crctab={}	
	temp=0
	crcinvtab={}
	for i in xrange(256):
		temp=crc32(0,i)
		crctab[i]=temp
		crcinvtab[temp >>24]=(temp<<8) ^ i
		
		
	return crctab,crcinvtab


def generate_Z15_2_table():
	z_15_2={key:[] for key in xrange(256)}
	for t in xrange(16384):#2^14
		temp=t<<2
		ki=(((temp^3)*(temp^2))>>8)&255
		#Associate with a ki temp values
		z_15_2[ki].append(temp)
	return z_15_2




def generate_Zi_1(i):
	possible_zi_15_2=z_15_2[keystream[-i]]
	
	#Based on the formula from section 3.1 in the paper
	zi_1=[]	
	counter=0
	for zi in Zi:
		
		zi_expr=((zi<<8)^crcinvtab[zi>>24])&64512
		for z in possible_zi_15_2:
			if (z&64512)==zi_expr:
				zi_1.append((((zi<<8)^crcinvtab[zi>>24])&4294901760)^z)
		
			
	return set(zi_1)
		
	



crctab,crcinvtab=init_crc()
z_15_2=generate_Z15_2_table()
	
unencrypted_archive=raw_input('Enter the name of the archive containing the plaintext file: ')

encrypted_archive=raw_input('Enter the name of the encrypted archive: ')	

plaintext=raw_input('Enter the name of the plaintext file in the archive: ')

with open(unencrypted_archive, "rb") as f, open(encrypted_archive, "rb") as g:
	keystream=[]
	#locate the start of the data in the unencrypted archive	
	unencrypted_file_size,unencrypted_data_start=locateData(f,plaintext)

	#locate the start of the data in the encrypted archive	
	encrypted_file_size,encrypted_data_start=locateData(g,plaintext)	
	
	#Move the current position in the file after the 12 bytes of the encryption header	
	encrypted_data_start+=12
	g.seek(12,1)	
	
	#Generate keystream bytes in keystream[]
	counter=unencrypted_file_size
	while(counter!=0):
		keystream+=[(ord(f.read(1))^ord(g.read(1)))]		
		counter-=1	

	
	#Generate first all Zn
	#Zi_15_2=calc_possible_t(keystream[-1])	
	Zi=[(y<<16)^temp for temp in z_15_2[keystream[-1]] for y in xrange(65536)]
	print "There are", len(Zi), "possible Zn keys"
	
	time=0
	#Reduce the number of Z using the extra plaintext and stopping at Z13
	counter=2
	while (counter < unencrypted_file_size-11):
		time1=datetime.datetime.now()
		Zi=generate_Zi_1(counter)
		time2=datetime.datetime.now()
		time+=(time2-time1).total_seconds()		
		print "There are", len(Zi) ,"Z lists left"		
		counter+=1
	print time

