import sys
import socket
import argparse
from datetime import datetime

#Checks if given IP address is valid.
def valid_ip(address):
	try:
		host_bytes = address.split('.')
		valid = [int(b) for b in host_bytes]
		valid = [b for b in valid if b >= 0 and b<=255]
		return len(host_bytes) == 4 and len(valid) == 4
	except:
		print("Invalid IP address.")
		sys.exit()

#Scans given IP from port 50-85. Accepts keyboard interrupt to end program.
def scan(target):
	print("-" * 50)
	print("Scanning target: "+target)
	print("Time started: "+str(datetime.now()))
	print("-" * 50)
	try:
		for port in range(50,85):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(1)
			result = s.connect_ex((target,port))
			if result == 0:
				print(f"Port {port} is open")
			s.close()
	except KeyboardInterrupt:
		print("\nExiting program.")
		sys.exit()

#Creates switches to choose between using hostname or IP	
parser = argparse.ArgumentParser(description = "Choose to use either a hostname or IP.")
parser.add_argument("-H", "--hostname", help = "Host name")
parser.add_argument("-ip", "--ipaddress", help = "Use IP")
args = vars(parser.parse_args())
target = sys.argv[2]

#Checks if given IP/Hostname is valid, then performs scan	
if args["ipaddress"]:
	valid_ip(target)
	scan(target)
elif args["hostname"]:
	try:
		target_ip = socket.gethostbyname(target)
		valid_ip(target_ip)
		scan(target_ip)
	except socket.gaierror:
		print("Hostname does not resolve to a valid IP.")