#
# START OF MINIFIED PYTHON SLOW AES
# Modified from the SlowAES project, http://code.google.com/p/slowaes/
#

_I='hex'
_H='invalid key size: %s'
_G='SIZE_192'
_F='SIZE_128'
_E='SIZE_256'
_D='CBC'
_C=True
_B=False
_A=None
import os,sys,math
def append_PKCS7_padding(s):A=16-len(s)%16;return s+A*chr(A)
def strip_PKCS7_padding(s):
	if len(s)%16 or not s:raise ValueError("String of len %d can't be PCKS7-padded"%len(s))
	A=ord(s[-1])
	if A>16:raise ValueError("String ending with %r can't be PCKS7-padded"%s[-1])
	return s[:-A]
class AES:
	keySize=dict(SIZE_128=16,SIZE_192=24,SIZE_256=32);sbox=[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];rsbox=[82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125]
	def getSBoxValue(A,num):return A.sbox[num]
	def getSBoxInvert(A,num):return A.rsbox[num]
	def rotate(A,word):return word[1:]+word[:1]
	Rcon=[141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203]
	def getRconValue(A,num):return A.Rcon[num]
	def core(B,word,iteration):
		A=word;A=B.rotate(A)
		for C in range(4):A[C]=B.getSBoxValue(A[C])
		A[0]=A[0]^B.getRconValue(iteration);return A
	def expandKey(E,key,size,expandedKeySize):
		F=expandedKeySize;B=size;A=0;G=1;C=[0]*F
		for H in range(B):C[H]=key[H]
		A+=B
		while A<F:
			D=C[A-4:A]
			if A%B==0:D=E.core(D,G);G+=1
			if B==E.keySize[_E]and A%B==16:
				for I in range(4):D[I]=E.getSBoxValue(D[I])
			for J in range(4):C[A]=C[A-B]^D[J];A+=1
		return C
	def addRoundKey(C,state,roundKey):
		A=state
		for B in range(16):A[B]^=roundKey[B]
		return A
	def createRoundKey(D,expandedKey,roundKeyPointer):
		A=[0]*16
		for B in range(4):
			for C in range(4):A[C*4+B]=expandedKey[roundKeyPointer+B*4+C]
		return A
	def galois_multiplication(C,a,b):
		A=0
		for D in range(8):
			if b&1:A^=a
			B=a&128;a<<=1;a&=255
			if B:a^=27
			b>>=1
		return A
	def subBytes(B,state,isInv):
		A=state
		if isInv:C=B.getSBoxInvert
		else:C=B.getSBoxValue
		for D in range(16):A[D]=C(A[D])
		return A
	def shiftRows(C,state,isInv):
		A=state
		for B in range(4):A=C.shiftRow(A,B*4,B,isInv)
		return A
	def shiftRow(C,state,statePointer,nbr,isInv):
		B=state;A=statePointer
		for D in range(nbr):
			if isInv:B[A:A+4]=B[A+3:A+4]+B[A:A+3]
			else:B[A:A+4]=B[A+1:A+4]+B[A:A+1]
		return B
	def mixColumns(D,state,isInv):
		B=state
		for A in range(4):C=B[A:A+16:4];C=D.mixColumn(C,isInv);B[A:A+16:4]=C
		return B
	def mixColumn(E,column,isInv):
		D=column
		if isInv:A=[14,9,13,11]
		else:A=[2,1,1,3]
		B=list(D);C=E.galois_multiplication;D[0]=C(B[0],A[0])^C(B[3],A[1])^C(B[2],A[2])^C(B[1],A[3]);D[1]=C(B[1],A[0])^C(B[0],A[1])^C(B[3],A[2])^C(B[2],A[3]);D[2]=C(B[2],A[0])^C(B[1],A[1])^C(B[0],A[2])^C(B[3],A[3]);D[3]=C(B[3],A[0])^C(B[2],A[1])^C(B[1],A[2])^C(B[0],A[3]);return D
	def aes_round(B,state,roundKey):A=state;A=B.subBytes(A,_B);A=B.shiftRows(A,_B);A=B.mixColumns(A,_B);A=B.addRoundKey(A,roundKey);return A
	def aes_invRound(B,state,roundKey):A=state;A=B.shiftRows(A,_C);A=B.subBytes(A,_C);A=B.addRoundKey(A,roundKey);A=B.mixColumns(A,_C);return A
	def aes_main(B,state,expandedKey,nbrRounds):
		E=nbrRounds;C=expandedKey;A=state;A=B.addRoundKey(A,B.createRoundKey(C,0));D=1
		while D<E:A=B.aes_round(A,B.createRoundKey(C,16*D));D+=1
		A=B.subBytes(A,_B);A=B.shiftRows(A,_B);A=B.addRoundKey(A,B.createRoundKey(C,16*E));return A
	def aes_invMain(B,state,expandedKey,nbrRounds):
		E=nbrRounds;C=expandedKey;A=state;A=B.addRoundKey(A,B.createRoundKey(C,16*E));D=E-1
		while D>0:A=B.aes_invRound(A,B.createRoundKey(C,16*D));D-=1
		A=B.shiftRows(A,_C);A=B.subBytes(A,_C);A=B.addRoundKey(A,B.createRoundKey(C,0));return A
	def encrypt(A,iput,key,size):
		C=size;E=[0]*16;B=0;D=[0]*16
		if C==A.keySize[_F]:B=10
		elif C==A.keySize[_G]:B=12
		elif C==A.keySize[_E]:B=14
		else:return _A
		J=16*(B+1)
		for F in range(4):
			for G in range(4):D[F+G*4]=iput[F*4+G]
		K=A.expandKey(key,C,J);D=A.aes_main(D,K,B)
		for H in range(4):
			for I in range(4):E[H*4+I]=D[H+I*4]
		return E
	def decrypt(A,iput,key,size):
		C=size;E=[0]*16;B=0;D=[0]*16
		if C==A.keySize[_F]:B=10
		elif C==A.keySize[_G]:B=12
		elif C==A.keySize[_E]:B=14
		else:return _A
		J=16*(B+1)
		for F in range(4):
			for G in range(4):D[F+G*4]=iput[F*4+G]
		K=A.expandKey(key,C,J);D=A.aes_invMain(D,K,B)
		for H in range(4):
			for I in range(4):E[H*4+I]=D[H+I*4]
		return E
class AESModeOfOperation:
	aes=AES();modeOfOperation=dict(OFB=0,CFB=1,CBC=2)
	def convertString(F,string,start,end,mode):
		C=end;B=start
		if C-B>16:C=B+16
		if mode==F.modeOfOperation[_D]:A=[0]*16
		else:A=[]
		D=B;E=0
		while len(A)<C-B:A.append(0)
		while D<C:A[E]=ord(string[D]);E+=1;D+=1
		return A
	def encrypt(E,stringIn,mode,key,size,IV):
		K=mode;I=size;H=key;G=stringIn
		if len(H)%I:return _A
		if len(IV)%16:return _A
		D=[];F=[0]*16;C=[];B=[0]*16;N=[];J=_C
		if G!=_A:
			for P in range(int(math.ceil(float(len(G))/16))):
				O=P*16;L=P*16+16
				if L>len(G):L=len(G)
				D=E.convertString(G,O,L,K)
				if K==E.modeOfOperation['CFB']:
					if J:C=E.aes.encrypt(IV,H,I);J=_B
					else:C=E.aes.encrypt(F,H,I)
					for A in range(16):
						if len(D)-1<A:B[A]=0^C[A]
						elif len(C)-1<A:B[A]=D[A]^0
						elif len(D)-1<A and len(C)<A:B[A]=0^0
						else:B[A]=D[A]^C[A]
					for M in range(L-O):N.append(B[M])
					F=B
				elif K==E.modeOfOperation['OFB']:
					if J:C=E.aes.encrypt(IV,H,I);J=_B
					else:C=E.aes.encrypt(F,H,I)
					for A in range(16):
						if len(D)-1<A:B[A]=0^C[A]
						elif len(C)-1<A:B[A]=D[A]^0
						elif len(D)-1<A and len(C)<A:B[A]=0^0
						else:B[A]=D[A]^C[A]
					for M in range(L-O):N.append(B[M])
					F=C
				elif K==E.modeOfOperation[_D]:
					for A in range(16):
						if J:F[A]=D[A]^IV[A]
						else:F[A]=D[A]^B[A]
					J=_B;B=E.aes.encrypt(F,H,I)
					for M in range(16):N.append(B[M])
		return K,len(G),N
	def decrypt(N,cipherIn,originalsize,mode,key,size,IV):
		E=originalsize;B=cipherIn
		if len(key)%size:return _A
		if len(IV)%16:return _A
		F=[];K=[];G=[];C=[0]*16;L='';M=_C
		if B!=_A:
			for H in range(int(math.ceil(float(len(B))/16))):
				I=H*16;D=H*16+16
				if H*16+16>len(B):D=len(B)
				F=B[I:D];G=N.aes.decrypt(F,key,size)
				for A in range(16):
					if M:C[A]=IV[A]^G[A]
					else:C[A]=K[A]^G[A]
				M=_B
				if E is not _A and E<D:
					for J in range(E-I):L+=chr(C[J])
				else:
					for J in range(D-I):L+=chr(C[J])
				K=F
		return C
def encryptData(key,data,mode=AESModeOfOperation.modeOfOperation[_D]):
	C=mode;B=data;A=key;A=list(map(ord,A))
	if C==AESModeOfOperation.modeOfOperation[_D]:B=append_PKCS7_padding(B)
	D=len(A);assert D in list(AES.keySize.values()),_H%D;E=[ord(A)for A in os.urandom(16)];F=AESModeOfOperation();C,H,G=F.encrypt(B,C,A,D,E);return ''.join(map(chr,E))+''.join(map(chr,G))
def decryptData(key,data,mode=AESModeOfOperation.modeOfOperation[_D]):
	B=data;A=key;A=list(map(ord,A));C=len(A);assert C in list(AES.keySize.values()),_H%C;E=list(map(ord,B[:16]));B=list(map(ord,B[16:]));F=AESModeOfOperation();D=F.decrypt(B,_A,mode,A,C,E)
	if mode==AESModeOfOperation.modeOfOperation[_D]:D=strip_PKCS7_padding(D)
	return D
def generateRandomKey(keysize):
	A=keysize
	if A not in(16,24,32):B='Invalid keysize, %s. Should be one of (16, 24, 32).';raise ValueError(B%A)
	return os.urandom(A)
def encrypt(plaintext,key):A=plaintext;B=A if not len(A)%16 else A+' '*(16*(len(A)/16+1)-len(A));C=AES();return ''.join(map(chr,C.encrypt(list(map(ord,B)),list(map(ord,key)),16))).encode(_I)
def decrypt(cipher,key):
	A=AES()
	try:B=cipher.decode(_I)
	except TypeError:raise
	return ''.join(map(chr,A.decrypt(list(map(ord,B)),list(map(ord,key)),16))).strip()

#
# END OF MINIFIED PYTHON SLOW AES
#