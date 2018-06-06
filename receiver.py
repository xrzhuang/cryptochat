#!/usr/bin/env python3
#receiver.py

import os, sys, getopt, time
from netinterface import network_interface
from securechannel import msg_receiver, state
from keyexchange import key_sender, key_receiver

NET_PATH = './'
OWN_ADDR = 'B'
NEW = False

# ------------       
# main program
# ------------

def check_old_messages():

	statefile = OWN_ADDR + '-statefile.txt'
	ifile = open(statefile, 'rt')
	line = ifile.readline() # skip enckey
	line = ifile.readline()
	msgs_read = line[len("received "):]
	msgs_read = int(msgs_read, base=10)

	in_dir = NET_PATH + OWN_ADDR + '/IN'
	msgs = sorted(os.listdir(in_dir))
	msgs_received = len(msgs)

	for i in range(msgs_read, msgs_received):
		try:
			with open(in_dir + '/' + msgs[i], 'rb') as f: msg = f.read()
			my_receiver = msg_receiver(OWN_ADDR)
			decrypted_msg = my_receiver.process(msg) 
			print(decrypted_msg)
		except:
			pass

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:n:', longopts=['help', 'path=', 'addr=', 'new'])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr> [--new]')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-n' or opt == '--new':
		NEW = True

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)


try: 
	check_old_messages()
except: # maybe state files have disappeared
	pass

netif = network_interface(NET_PATH, OWN_ADDR)

if NEW:
	# reads key that was sent
	while (True):
		rkeymsg = netif.receive_keymsg()
		if rkeymsg is not None:
			break

	# rkeymsg =  netif.receive_keymsg()

	mykey_receiver = key_receiver(OWN_ADDR)
	s, rkey = mykey_receiver.process(rkeymsg) # assuming this is a tuple and not returned false, the receiver is verified
	# sends key back
	mykey_sender = key_sender(OWN_ADDR)
	keymsg = mykey_sender.send(rkey, s)
	netif.send_keymsg(keymsg, s)

	# key exchange protocol finished
	state.reset(OWN_ADDR, rkey)
	# print("Key exchange protocol finished")

# main loop
print('Main loop started...')
while True:
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
	my_receiver = msg_receiver(OWN_ADDR)
	decrypted_msg = my_receiver.process(msg) 
	print(decrypted_msg)
    
