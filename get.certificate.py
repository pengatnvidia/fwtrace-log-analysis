
# Python code to check sys logs

import sys
import binascii
import hashlib

class Cert:
	def __init__(self, slot):
		self.slot = slot
		self.off = 0
		self.length = 0
		self.portion = 0
		self.roothash = ""
		self.reminder = 0
		self.certchain = ""
		self.header = ""

	def req(self, slot, off):
		if slot != self.slot:
			print(f"different slot: request {slot}, uncomplete slot{slot}")
			return
		self.off = off
		if off+self.reminder == self.length :
			print("request off good")
			return True
		else:
			print("ERROR: request wrong off")
			return False
	
	def resp_portion(self, slot, portion, reminder, length):
		if slot != self.slot:
			print(f"different slot: request {slot}, uncomplete slot{slot}")
			return
		if length > 0:
			if length == (portion+reminder):
				print("cert length correct")
			else:
				print("ERROR: cert length incorrect")
			self.length = length
		self.portion = portion
		self.reminder = reminder
		if portion + reminder + self.off == self.length :
			return True
		else:
			print("ERROR: response wrong portion")
			return False		

	def resp_roothash(self, header, roothash):
		self.header = header
		self.roothash = roothash

	def resp_cert(self, portion):
		self.certchain += portion	

	def get_complete(self):
		if self.reminder == 0 :
			slot_mask = str(1<< self.slot)
			print(f"slot mask = {slot_mask}")
			print(f"length(includes cert.header+roothash)={self.length}:  header.4B={self.header} roothash.48B={self.roothash}")
			print(self.certchain)
			chain_bytes = binascii.unhexlify(self.certchain )
			calc_digest = hashlib.sha384(chain_bytes).digest()
			print(f"slot mask = {slot_mask} calculated certchain hash = {calc_digest.hex()}")	
			fulldata = self.header + self.roothash + self.certchain
			full_bytes = binascii.unhexlify( fulldata )
			full_hash = hashlib.sha384(full_bytes).digest()		
			print(f"calculated certchain hash(including header+roothash) = {full_hash.hex()}")		
			return True
		return False
		

def get_inline_attr(line, attr):
	items = line.split()
	for item in items:
		kvs = item.strip().split("=")
		if len(kvs) == 2 :
			k = kvs[0].strip()
			v = kvs[1].strip()
			attr[k] = v	

def decodecert(Lines):
	lineid = 0

	cert = None
	for line in Lines:		
		if "Challenge_CertChainHash" in line:
			attr = {}
			get_inline_attr(line, attr)
			slot_mask = attr.get("Param2_slot_mask", "")
			hashvalue = attr.get("Challenge_CertChainHash", "")
			if hashvalue and slot_mask :
				print(f"slot_mask = {slot_mask}  CHALLENGE_certchain_hash = {hashvalue}")	
		if "get_digest" in line:
			attr = {}
			get_inline_attr(line, attr)
			slot_mask = attr.get("Param2_Slot_mask", "")
			hashvalue = attr.get("get_digest", "")
			if hashvalue and slot_mask :
				print(f"slot_mask = {slot_mask}  get_digest = {hashvalue}")					
		
		if "get_certificate_off" in line:
			attr = {}
			get_inline_attr(line, attr)
			slot = attr.get("Param1_Slot", "")
			off = attr.get("get_certificate_off", "")
			if slot and off :
				if "0" == off :
					cert = Cert(0)
				elif cert:
					if not cert.req( int(slot), int(off) ):
						cert = None

		if "get_certificate_portion" in line:
			attr = {}
			get_inline_attr(line, attr)
			slot = attr.get("get_certificate_slot", "")
			portion = attr.get("get_certificate_portion", "")	
			reminder = attr.get("get_certificate_remainder", "")	
			lengthstr = attr.get("get_certificate_length", "")
			if cert:
				length = 0
				if lengthstr :
					length = int(lengthstr)
				if not cert.resp_portion(int(slot), int(portion), int(reminder), length ):
					cert = None

		if "get_certificate_root_hash" in line:
			attr = {}
			get_inline_attr(line, attr)
			roothash = attr.get("get_certificate_root_hash", "")
			certheader = attr.get("get_certificate_header", "")
			if cert:
				cert.resp_roothash(certheader, roothash)	
		if "get_certificate_cert" in line:
			attr = {}
			get_inline_attr(line, attr)
			certportion = attr.get("get_certificate_cert", "")
			if cert:
				cert.resp_cert(certportion)	
				if cert.get_complete() :
					cert = None

def main():
	tfile = ""
	argc = len(sys.argv)

	if( argc > 1 ):
		tfile = sys.argv[1]
	else:
		print("no input fw trace analysis file")
		return
		
	file1 = open(tfile, 'r')
	Lines = file1.readlines()

	decodecert( Lines )
    
if __name__=='__main__':
	main()


