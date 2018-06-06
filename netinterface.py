#!/usr/bin/env python3
# netinterface.py

import os, time

class network_interface:
    timeout = 0.800  # 800 millisec
    addr_space = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    own_addr = ''
    net_path = ''
    last_read = -1

    def __init__(self, path, addr):
        self.net_path = path
        self.own_addr = addr

        addr_dir = self.net_path + self.own_addr
        if not os.path.exists(addr_dir):
            os.mkdir(addr_dir)
            os.mkdir(addr_dir + '/IN')
            os.mkdir(addr_dir + '/OUT')

        in_dir = addr_dir + '/IN'
        msgs = sorted(os.listdir(in_dir))
        self.last_read = len(msgs) - 1

    def send_keymsg(self, keymsg, dst=''):
        out_dir = self.net_path + 'S' + '/IN'

        import datetime
        timestamp = str(datetime.datetime.utcnow())
        with open(out_dir + '/' + timestamp + '-' + self.own_addr + dst, 'wb') as f: f.write(keymsg)
        return True

        '''
        if os.path.isfile(out_dir + '/' + self.own_addr):
            with open(out_dir + '/' + self.own_addr, 'wb') as f: f.write(keymsg)
            return True
        else:
            return False
        '''

    def receive_keymsg(self, dst=''):
        in_dir = self.net_path + 'S' + '/OUT'
        if os.path.isfile(in_dir + '/' + dst + self.own_addr):
            with open(in_dir + '/' + self.own_addr + dst, 'rb') as f: key = f.read()
            os.remove(in_dir + '/' + self.own_addr + dst)
            return key
        else:
            return None

    def send_msg(self, dst, msg):
        out_dir = self.net_path + self.own_addr + '/OUT'
        msgs = sorted(os.listdir(out_dir))

        if len(msgs) > 0:
            last_msg = msgs[-1].split('--')[0]
            try:
                next_msg = (int.from_bytes(bytes.fromhex(last_msg), byteorder='big') + 1).to_bytes(2,
                                                                                                   byteorder='big').hex()
            except:
                next_msg = '0000'
        else:
            next_msg = '0000'

        next_msg += '--' + dst
        with open(out_dir + '/' + next_msg, 'wb') as f:
            f.write(msg)

        return True


    def receive_msg(self, blocking=False):
        in_dir = self.net_path + self.own_addr + '/IN'

        status = False
        msg = b''

        while True:
            msgs = sorted(os.listdir(in_dir))
            if len(msgs) - 1 > self.last_read:
                with open(in_dir + '/' + msgs[self.last_read + 1], 'rb') as f: msg = f.read()
                status = True
                self.last_read += 1

            if not blocking or status:
                return status, msg
            else:
                time.sleep(self.timeout)
