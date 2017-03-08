# Tom Kremer
# Ben Krausz

from sys import argv, stdout
from socket import socket

from OpenSSL import SSL
from OpenSSL import crypto

def main():
	sock = socket()
	mycontext = SSL.Context(SSL.TLSv1_METHOD)
	myconn = SSL.Connection(mycontext, sock)
	
	myconn.connect(('www.facebook.com', 443))
	myconn.do_handshake()

	print "Connection established"

	print myconn.getpeername()
	print myconn.state_string()
	print myconn.sendall("testing")
	print "Sent that ish"

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
