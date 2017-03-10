# Tom Kremer
# Ben Krausz

from sys import argv, stdout
from socket import socket
import re
import datetime

from OpenSSL import SSL
from OpenSSL import crypto

"""
Things that are put on hold:
Comparing to list of trusted CAs
doesn't work for stanford.edu (related to www-aws?)
"""

def main():

	url = "www.facebook.com"
	# Setting up socket, context, and connection
	sock = socket()
	mycontext = SSL.Context(SSL.TLSv1_METHOD)
	# mycontext.set_tmp_ecdh(crypto.get_elliptic_curves())
	myconn = SSL.Connection(mycontext, sock)
	
	# Connecting to a website and exchanging keys
	myconn.connect((url, 443))
	myconn.do_handshake()

	print "Connection established"

	cert = myconn.get_peer_certificate()
	cert_chain = myconn.get_peer_cert_chain()
	print cert_chain

	# The browser checks that the certificate was issued by a trusted party 
	# (usually a trusted root CA), that the certificate is still valid and 
	# that the certificate is related to the site contacted.
	for i in xrange(len(cert_chain)):
		name_obj = cert_chain[i].get_subject()
		print name_obj.commonName.decode()

		start_date = int(cert_chain[i].get_notBefore()[:-1])
		exp_date = int(cert_chain[i].get_notAfter()[:-1])
		now = int(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S"))

		if not (start_date < now < exp_date):
			print "Not in valid time"
			# THROW ERROR HERE
			break
			
		# print cert.get_pubkey()
		# print cert.get_pubkey().bits()
		# print cert.get_signature_algorithm()

		if i == 0:
			print cert_chain[i].get_pubkey()
			regex = name_obj.commonName.decode().replace('.', r'\.').replace('*',r'.*') + '$'
			print regex
			if re.match(regex, url):
				print "It's a match!"
			else:
				print "No match!"

		print

	return



	# Sending a dummy message to poke website and get error message page
	# Should be sending some sort of GET request
	print myconn.getpeername()
	print myconn.state_string()
	myconn.sendall("GET / HTTPS/1.1") # HTTP/1.1
	print "Sent that ish"

	# Receiving Facebook's error page html
	t1 = []
	try:
		while True:
			r = myconn.recv(8192)
			t1.append(r)
	except SSL.ZeroReturnError:
		pass

	myconn.shutdown()
	myconn.close()
	print "".join(t1)



if __name__ == "__main__":
	main()
