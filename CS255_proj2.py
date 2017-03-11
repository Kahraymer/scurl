# Tom Kremer
# Ben Krausz

from sys import argv, stdout
import socket
import re
import datetime

from OpenSSL import SSL
from OpenSSL import crypto

"""
Things that are put on hold:
Comparing to list of trusted CAs
doesn't work for stanford.edu (related to www-aws?)
"""
url = ""

def cb_func(conn, cert, errno, errdepth, ok):
	global url
	print "testing"
	print "errno: ", errno
	print "errdepth: ", errdepth


	# Checking name on leaf certificate (doesn't work)

	""" 
	NOTES:
	Also it allows wildcards on any place which is against the rule that 
	wildcards should only be allowed in the leftmost label: *.example.com 
	is fine while www.*.com or even *.*.* is not allowed but accepted by your code.
	"""


	# if errdepth == 0:
	# 	regex = cert.get_subject().commonName.decode().replace('.', r'\.').replace('*',r'.*') + '$'
		# print regex
	# 	if re.match(regex, url):
	# 	if cert.get_subject().commonName != url:
			# print "Certificate name doesn't match host"
			# return False

	if (errno == 9 or errno == 10):
		print "Not in valid time"
		return False
	else:
		print "Valid time"

	# start_date = int(cert.get_notBefore()[:-1])
	# exp_date = int(cert.get_notAfter()[:-1])
	# now = int(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S"))

	# if not (start_date < now < exp_date):
	# 	print "Not in valid time"
	# 	# THROW ERROR HERE!
	# 	return False
	# else:
	# 	print "Valid time :)"

	return ok



def main():
	global url

	url = "www.google.com"
	# Setting up socket, context, and connection
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	mycontext = SSL.Context(SSL.TLSv1_METHOD)

	mycontext.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, cb_func)
	mycontext.set_default_verify_paths()
	"""
	Context.set_default_verify_paths()
	Context.set_cipher
	Context.set_verify
	Write a callback
	"""

	#date is valid
	#name matches
	#paths are verified

	# mycontext.set_tmp_ecdh(crypto.get_elliptic_curves())
	myconn = SSL.Connection(mycontext, sock)

	myconn.set_tlsext_host_name("server")
	myconn.set_connect_state()
	
	# Connecting to a website and exchanging keys
	print url

	myconn.connect((url, 443))

	try:
		myconn.do_handshake()
	except (SSL.ZeroReturnError, SSL.Error):
		print "Invalid certificate"
		return

	print "Connection established"

	cert = myconn.get_peer_certificate()
	cert_chain = myconn.get_peer_cert_chain()
	print cert_chain
	#mycontext.set_options()

	# The browser checks that the certificate was issued by a trusted party 
	# (usually a trusted root CA), that the certificate is still valid and 
	# that the certificate is related to the site contacted.
	'''
	for i in xrange(len(cert_chain)):
		name_obj = cert_chain[i].get_subject()
		print name_obj.commonName.decode()

		start_date = int(cert_chain[i].get_notBefore()[:-1])
		exp_date = int(cert_chain[i].get_notAfter()[:-1])
		now = int(datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S"))

		if not (start_date < now < exp_date):
			print "Not in valid time"
			# THROW ERROR HERE!
			break

		if i == 0:
			print cert_chain[i].get_pubkey()
			regex = name_obj.commonName.decode().replace('.', r'\.').replace('*',r'.*') + '$'
			print regex
			if re.match(regex, url):
				print "It's a match!"
			else:
				print "No match!"
	'''

	# return

	# Sending a dummy message to poke website and get error message page
	# Should be sending some sort of GET request
	print myconn.getpeername()
	print myconn.state_string()
	myconn.sendall("GET / HTTP/1.1\r\nHost: " + url + "\r\nUser-Agent: Tom and Ben\r\n\r\n") # HTTP/1.1
	print "Sent a GET"

	t1 = []
	try:
		numBytes = 1024
		while True:
			# if len(r) == 0:
			# 	print "DONE!"
			r = myconn.recv(numBytes)
			t1.append(r)
			if len(r) < numBytes and "</html>" in r:
				print "DONE!"
				break
	except (SSL.ZeroReturnError, SSL.Error):
		pass

	myconn.shutdown()
	myconn.close()
	# print "".join(t1)



if __name__ == "__main__":
	main()