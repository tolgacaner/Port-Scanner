
#Author: Tolga CANER

from threading import *
from socket import *
import optparse
from termcolor import colored

def connectScan(targetHost,targetPort):
	try:
		sock = socket(AF_INET,SOCK_STREAM) # TCP connection creation.
		sock.connect((targetHost,targetPort)) # Connecting to the port of the host given as a parameter.
		print(colored("[+] %d/tcp open" %targetPort,'green'))
	except:
		print(colored("[-] %d/tcp closed" %targetPort,'red'))
	finally:
		sock.close()

def portScan(targetHost,targetPorts):
	try:
		targetIP = gethostbyname(targetHost)
	except:
		print("Unknown Host: %s" %targetHost)
	try:
		targetName = gethostbyaddr(targetIP)
		print("[+] " + targetName[0] + "search results for")
	except:
		print("[+] " + targetIP + "search results for")
	setdefaulttimeout(1)
	for targetPort in targetPorts:
		t = Thread(target=connectScan,args=(targetHost,int(targetPort)))
		t.start()

def main():
	parser = optparse.OptionParser("Using the program : " + "-H <Destination IP>"
				      + " -p <Destination IP>")
	parser.add_option('-H',dest='targetHost',type='string',help='Enter the specified Destination IP Address or Domain')
	parser.add_option('-p',dest='targetPort',type='string',help='Enter the specified Destination Port or Ports separated by commas')
	(options,args) = parser.parse_args()
	targetHost = options.targetHost
	targetPorts = str(options.targetPort).split(',')
	if (targetHost == None) | (targetPorts[0] == None):
		print(parser.usage)
		exit(0) 
	portScan(targetHost,targetPorts)

if __name__ == '__main__':
	main()
