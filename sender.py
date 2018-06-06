#!/usr/bin/env python3
# sender.py

import os, sys, getopt, time
from netinterface import network_interface
from securechannel import msg_sender, state
from keyexchange import key_sender, key_receiver

NET_PATH = './'
OWN_ADDR = 'A'
NEW = False

# ------------       
# main program
# ------------

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:n:', longopts=['help', 'path=', 'addr=', 'new'])
except getopt.GetoptError:
    print('Usage: python sender.py -p <network path> -a <own addr> [--new]')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python sender.py -p <network path> -a <own addr>')
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

# send key
all_dst = input('Type a destination address: ')
netif = network_interface(NET_PATH, OWN_ADDR)

if NEW:
    mykey_sender = key_sender(OWN_ADDR)
    symkey = mykey_sender.generate()
    for dst in all_dst:
        keymsg = mykey_sender.send(symkey, dst)
        netif.send_keymsg(keymsg, dst)

        # while True: while loop to wait to recieve the recievers message
        while (True):
            rkeymsg = netif.receive_keymsg()
            if rkeymsg is not None:
                break

        # check if the key received is the same
        mykey_receiver = key_receiver(OWN_ADDR)
        r, rkey = mykey_receiver.process(rkeymsg)
        if (rkey == symkey) and (r == dst):
            state.reset(OWN_ADDR, symkey)
            # certified destinations or total group fail
            # print("Key exchange protocol complete")
        else:
            print("Key exchange protocol with " + dst + " failed")


# main loop
print('Main loop started...')
while True:
    msg = input('Type a message: ')

    for dst in all_dst:
        my_sender = msg_sender(OWN_ADDR, dst)
        encrypted_msg = my_sender.generate(msg.encode('utf-8'))

        netif.send_msg(dst, encrypted_msg)

    if input('Continue? (y/n): ') == 'n': break
