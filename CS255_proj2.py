#!/usr/bin/python


"""
in directory, type:
chmod 755 scurl
now it works
"""

# Tom Kremer
# Ben Krausz

from sys import argv, stdout
import socket
import re
import datetime
from urlparse import urlparse

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


"""
Constructs a parsed url
url_object = {
	common_name: "www.google.com",
	port: 443 (int)
	path: '/hello'

}
"""
def parse_url(url):

	if url.startswith('//'):
		url = 'https:' + url

	if url.startswith('http://'):
		url = url[:4] + 's' + url[4:]

	if not url.startswith('https://'):
		url = "https://" + url

	if url[8:11] != 'www':
		url = url[:8] + 'www.' + url[8:]
	
	parsed_url = urlparse(url)
	# ParseResult(scheme='http', netloc='www.cwi.nl:80', path='/%7Eguido/Python.html',
    #        params='', query='', fragment='')
	print parsed_url

	url_object = {}

	if len(parsed_url.netloc) > 0:
		if ":" in parsed_url.netloc:
			index = parsed_url.netloc.find(":")
			url_object['common_name'] = parsed_url.netloc[:index]
			url_object['port'] = int(parsed_url.netloc[index+1:])
		else:
			url_object['common_name'] = parsed_url.netloc
			url_object['port'] = 443

		# Path is just everything after the common name and/or port
		url_object['path'] = url.split(parsed_url.netloc)[1]
		if len(url_object['path']) == 0:
			url_object['path'] = '/'
	else:
		return None

	return url_object



def main():
	global url

	url = "https://www.google.com"


	url_object = parse_url(url)

	print url_object['common_name']
	print url_object['port']
	print url_object['path']

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

	myconn = SSL.Connection(mycontext, sock)

	myconn.set_tlsext_host_name("server")
	myconn.set_connect_state()

	myconn.connect((url_object['common_name'], url_object['port']))

	try:
		myconn.do_handshake()
	except (SSL.ZeroReturnError, SSL.Error):
		print "Invalid certificate"
		return

	print "Connection established"

	# cert = myconn.get_peer_certificate()
	cert_chain = myconn.get_peer_cert_chain()
	print cert_chain
	#mycontext.set_options()

	# The browser checks that the certificate was issued by a trusted party 
	# (usually a trusted root CA), that the certificate is still valid and 
	# that the certificate is related to the site contacted.
	print myconn.state_string()
	myconn.sendall("GET " + url_object['path'] + " HTTP/1.1\r\nHost: " + url_object['common_name'] + "\r\nUser-Agent: Tom and Ben\r\n\r\n") # HTTP/1.1
	print "Sent a GET to: " + "GET " + url_object['path'] + " HTTP/1.1\r\nHost: " + url_object['common_name'] + "\r\nUser-Agent: Tom and Ben\r\n\r\n"

	t1 = []
	try:
		numBytes = 1024
		while True:
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