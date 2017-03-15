#!/usr/bin/python
#anity check, run this line if scurl is in the current directory:
# /usr/class/cs255/bin/sanity/sanity $PWD/scurl

"""
to make it a shell command:
1) rename the file to just "scurl"
in directory, type:
chmod +x scurl
now it works as a shell command
"""

# Tom Kremer
# Ben Krausz

import sys
from sys import argv, stdout
import socket
import re
import datetime
from urlparse import urlparse
import copy

from OpenSSL import SSL
from OpenSSL import crypto

"""
Things that are put on hold:
catch unexpected EOF and treat them as 0 error
"""
url_object = {}
tls_version = SSL.TLSv1_2_METHOD
tls_map = {
	"--tlsv1.0": SSL.TLSv1_METHOD,
	"--tlsv1.1": SSL.TLSv1_1_METHOD,
	"--tlsv1.2": SSL.TLSv1_2_METHOD,
	"--sslv3": SSL.SSLv3_METHOD,
}


flagmap = {
	"--ciphers": False,
	"--crlfile": False,
	"--cacert": False,
	"--allow-stale-certs": False,
	"pinnedcertificate": False}

def verify_cipher_args(args):
	#DO WE ONLY NEED THIS TO WORK FOR CORN CIPHERS?????
	ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:SRP-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:PSK-3DES-EDE-CBC-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:PSK-AES128-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:PSK-RC4-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA"
	cipherlist = ciphers.split(":")
	arglist = args.split(":")
	for arg in arglist:
		if(arg not in cipherlist):
			#print arg + " not in cipherlist"
			return False
	return True



def parse_args():
	global tls_map, tls_version

	#print 'Number of arguments:', len(sys.argv), 'arguments.'
	#print 'Argument List:', str(sys.argv)
	i = 1
	while(i < len(sys.argv)):
		if (sys.argv[i] in tls_map):
			tls_version = tls_map[sys.argv[i]]
	
		elif(sys.argv[i]=='--cacert'):
			#NEED TO CONFIRM FILE IS VALID
			if(i+1 < len(sys.argv)):
				flagmap['--cacert']= sys.argv[i+1]
				i=i+2
				continue
			else:
				sys.stderr.write("scurl: try 'scurl --help' or 'scurl --manual' for more information")
				exit(1)

		elif(sys.argv[i]=='--crlfile'):
			#NEED TO CONFIRM FILE IS VALID
			if(i+1 < len(sys.argv)):
				flagmap['--crlfile']=sys.argv[i+1]
				i=i+2
				continue
			else:
				sys.stderr.write("scurl: try 'scurl --help' or 'scurl --manual' for more information")
				exit(1)


		elif(sys.argv[i]=='--pinnedcertificate'):
			#NEED TO CONFIRM FILE IS VALID
			if(i+1 < len(sys.argv)):
				flagmap['--pinnedcertificate']=sys.argv[i+1]
				i=i+2
				continue
			else:
				sys.stderr.write("scurl: try 'scurl --help' or 'scurl --manual' for more information")
				exit(1)

		elif(sys.argv[i]=='--allow-stale-certs'):
			if(i+1 < len(sys.argv) and sys.argv[i+1].isdigit() and sys.argv[i+1]>=0):
				print 'allow stale certs by ' + sys.argv[i+1] + ' days'
				flagmap["--allow-stale-certs"]= sys.argv[i+1]
				i=i+2
				continue
			else:
				sys.stderr.write('--allow-stale-certs invalid N')
				exit(1)

		elif(sys.argv[i]=='--ciphers'):
			#NEED TO CONFIRM CIPHERS ARE VALID
			if(i+1 < len(sys.argv) and verify_cipher_args(sys.argv[i+1])):
				flagmap['--ciphers']=sys.argv[i+1]
				i=i+2
				continue
			else:
				sys.stderr.write( "scurl: try 'scurl --help' or 'scurl --manual' for more information")
				exit(1)
		elif not (parse_url(sys.argv[i])):
			sys.stderr.write("scurl: try 'scurl --help' or 'scurl --manual' for more information")
			exit(1)

		i=i+1
	#print flagmap
	return True



def cb_func(conn, cert, errno, errdepth, ok):
	global url_object

	# Checking name on leaf certificate (doesn't work)

	""" 
	NOTES:
	Also it allows wildcards on any place which is against the rule that 
	wildcards should only be allowed in the leftmost label: *.example.com 
	is fine while www.*.com or even *.*.* is not allowed but accepted by your code.
	"""

	if errdepth == 0:
		
		pattern = copy.deepcopy(cert.get_subject().commonName)
		
		num_dots1 = cert.get_subject().commonName.count('.')
		num_dots2 = url_object['common_name'].count('.')
		if num_dots1 != num_dots2:
			# An exception for wildcards. *.google.com should be accepted by google.com
			if not ((cert.get_subject().commonName[:2] == '*.') and (cert.get_subject().commonName[2:] == url_object['common_name'])):


				# Wildcard character introduced new periods, which isn't allowed
				return False
		if pattern.rfind('*') > pattern.find('.'):
			# Asterisk not in left section
			return False
		
		pattern = pattern.replace('.', r'\.').replace('*', r'.*')
		# print url_object['common_name']
		# print pattern
		if not re.match(pattern, url_object['common_name']):
			return False		

	# if errdepth == 0:
	# 	regex = cert.get_subject().commonName.decode().replace('.', r'\.').replace('*',r'.*') + '$'
		# print regex
	# 	if re.match(regex, url):
	# 	if cert.get_subject().commonName != url:
			# print "Certificate name doesn't match host"
			# return False

	if (errno == 9 or errno == 10):
		# print "Not in valid time"
		return False
	# else:
		# print "Valid time"

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
	path: '/path'
}
Returns none if invalid url type
"""
def parse_url(url):
	global url_object	
	#print url
	if url.startswith('//'):
		url = 'https:' + url

	if url.startswith('http://'):
		url = url[:4] + 's' + url[4:]

	if not url.startswith('https://'):
		url = "https://" + url
	
	parsed_url = urlparse(url)
	# ParseResult(scheme='http', netloc='www.cwi.nl:80', path='/%7Eguido/Python.html',
    #        params='', query='', fragment='')
	# print parsed_url

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
		return False
	#print url_object
	return True

"""
Sets up the socket, context, and connection.
Returns a conenction object
"""
def establish_connection(url_obj):
	global tls_version

	# Setting up socket, context, and connection
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	myContext = SSL.Context(tls_version)
	if(flagmap['--ciphers'] != False):
		myContext.set_cipher_list(flagmap['--ciphers'].decode('utf-8'))
	myContext.set_default_verify_paths()
	
	"""
	Context.set_cipher
	"""

	myConnection = SSL.Connection(myContext, sock)

	myConnection.set_tlsext_host_name(url_obj['common_name'])
	myConnection.set_connect_state()

	myConnection.connect((url_obj['common_name'], url_obj['port']))

	return myConnection


def main():
	global url_object, tls_version
	parse_args()
	#url = "www.facebook.com"
	#worked = parse_url(url)
	#if not worked:
		# "Badly formatted url"
		# return

	myConnection = establish_connection(url_object)
	if myConnection is None:
		# print "Couldn't establish connection ???? "
		exit(1)

	try:
		myConnection.do_handshake()
	except (SSL.ZeroReturnError, SSL.Error):
		# print "Invalid certificate"
		exit(1)

	# print "Connection established"

	# print myConnection.state_string()

	#myContext.set_options()

	# The browser checks that the certificate was issued by a trusted party 
	# (usually a trusted root CA), that the certificate is still valid and 
	# that the certificate is related to the site contacted.
	myConnection.sendall("GET " + url_object['path'] + " HTTP/1.1\r\nHost: " + url_object['common_name'] + "\r\nUser-Agent: Tom and Ben\r\n\r\n") # HTTP/1.1

	t1 = []
	try:
		numBytes = 1024
		while True:
			r = myConnection.recv(numBytes)
			t1.append(r)
			if len(r) < numBytes and "</html>" in r:
				# print "DONE getting HTML"
				break
	except (SSL.ZeroReturnError, SSL.Error):
		pass



	myConnection.shutdown()
	myConnection.close()
	html_string = "".join(t1)
	# print html_string
	html_body_index = html_string.find('<!DOCTYPE html>')
	if html_body_index == -1:
		html_body_index = html_string.find('<!doctype html>')
	html_body = html_string[html_body_index:]
	end_tag = '</html>'
	end_index = html_body.find(end_tag)
	html_body = html_body[:end_index+len(end_tag)]
	print html_body
	exit(0)

if __name__ == "__main__":
	main()

