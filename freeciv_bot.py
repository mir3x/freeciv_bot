#!/usr/bin/python3
# -*- coding: latin-1 -*-

'''
@package freeciv_bot
'''

import socket
import sys
import struct
import array
import zlib
import io
import re
from argparse import ArgumentParser
from datetime import datetime

PJOIN_REQ = 4
PSTART = 0
JOIN_REPLY = 5
AUTH_REP = 7
PING = 88
PONG = 89
JUMBO_SIZE = 65535
COMPRESSION_BORDER = 16*1024+1
JUMBO_BORDER = 64*1024-COMPRESSION_BORDER-1

VERSION_20 = '+2.0 conn_ping_info username_info new_hack ReportFreezeFix AttrSerialFix extroutes extgameinfo exttechleakage voteinfo extglobalinfo+'
VERSION_25 = '+Freeciv-2.5-network nationset_change tech_cost split_reports extended_move_rate illness_ranges nonnatdef cheaper_small_wonders+'
VERSION_26 = '+Freeciv-2.6-network techloss_forgiveness+'

header_struct = struct.Struct('!H')
jumbo_struct = struct.Struct('!I')
prelogin_struct = struct.Struct('!HB')
frame_struct = struct.Struct('!HBB')
processing_started = struct.Struct('!c')
join_reply_struct = struct.Struct('!BsssI')
bool_struct = struct.Struct('!B')
char_struct = struct.Struct('!s')

def unpack_bool(fbytes):
    bbumbo = fbytes.read(1)
    (by, ) = bool_struct.unpack(bbumbo)
    return by

def unpack_string(fbytes):
    blocks = []
    while True:
      bbumbo = fbytes.read(1)
      (by, ) = char_struct.unpack(bbumbo)
      blocks.append(by)
      if by == b'\x00':
        break        
    return b''.join(blocks).decode('ascii')

def process_packet(pkt):
    f = io.BytesIO(pkt)
    
    bumbo = f.read(3)

    (plen, pkt_type,) = prelogin_struct.unpack(bumbo)

    ret = 0
    
    if pkt_type == JOIN_REPLY:
        if unpack_bool(f) == 0:
          print("Cannot join to server")
        print("LOGIN MESSAGE: ", unpack_string(f))
    if pkt_type == 6:
        print("AUTH REQ")
        ret = 6
    if pkt_type == 25:
        #4 bytes header after postlogin crap?
        if (f.getbuffer().nbytes) > 4:
            f.read(1)
        dateTimeObj = datetime.now()
        s = unpack_string(f)
        #remove colors
        #s = re.sub(r'\[[^)]*\]', "",s)
        print("{}:{}:{} CHAT: {}".format(dateTimeObj.hour,dateTimeObj.minute,dateTimeObj.second,s))
    # if pkt_type == 116:
    #     print("PACKET CONN PING INFO")
    if pkt_type == 244:
        print("TIMEOUT INFO")
    if pkt_type == PING:
        ret = PONG
    
    return ret

def process_jumbo(jumbo):
    f = io.BytesIO(jumbo)

    x = 0
    rets = []
    while True:
        blocks = []
        bumbo = f.read(3)
        if bumbo == b'':
          return rets
        blocks.append(bumbo)
        (lenx, pkt_type,) = prelogin_struct.unpack(bumbo)
        r = f.read(lenx - 3)
        blocks.append(r)
        rrrr = b''.join(blocks)
        #print("SENDING TO PROCESS", " ".join(["{:02}".format(x) for x in rrrr]))
        rets.append(process_packet(rrrr))
        #f.seek(lenx, 1)
        x += 1
    return rets

def recvall(sock, length, xdecompres):
    blocks = []
    while length:
        block = sock.recv(length)
        # print('block', block)
        # print('bytes left: ', length)
        if not block:
            raise EOFError('socket closed: %d bytes left'.format(length))
        length -= len(block)
        blocks.append(block)
    rep = b''.join(blocks)
    if xdecompres:
        #print("uncompressed :{}".format(len(rep)))
        rep = zlib.decompress(rep)
        #print("decompressed :{}".format(len(rep)))
    return rep


def get_block(sock):
    
    decompr = False
    is_jumbo = False
    blocks = []
    
    data = recvall(sock, header_struct.size, False)
    (block_length,) = header_struct.unpack(data)
    bl = block_length
    # print("HSZ", block_length)
    # print("HSZ data", data)
    if (block_length != JUMBO_SIZE) and (block_length < COMPRESSION_BORDER):
        blocks.append(data)
    
    if block_length == JUMBO_SIZE:
        is_jumbo = True
        data = recvall(sock, jumbo_struct.size, False)
        (bl,) = jumbo_struct.unpack(data)
        bl = bl - 4
        decompr = True
    elif block_length >=COMPRESSION_BORDER:
        decompr = True
        #data = recvall(sock, header_struct.size, False)
        bl = bl - COMPRESSION_BORDER
    block_length = bl
    y = recvall(sock, block_length - 2, decompr)
    blocks.append(y)
    return b''.join(blocks)

def put_block(sock, message):
    block_length = len(message)
    sock.send(header_struct.pack(block_length))
    sock.send(message)

def get_header(sock):
    header = sock.recv(2)
    x = struct.unpack('!H', header)
    return x[0]

def get_message(sock, len):
    sock.recv(len - 2)

def send_pong(sock):
    sock.sendall(put_size(pack_8bit([0, 0 , PONG,])))

def send_auth(sock, password):
    auth = pack_8bit([0, 0 , AUTH_REP , 1]) + bytes(password, 'ascii') + nullbyte()
    print("Sending password")
    sock.sendall(put_size(auth))

def ser_version(ver):
    return {
        20: VERSION_20,
        25: VERSION_25,
        26: VERSION_26
    }[ver]

def pack_8bit(lista):
    r = b''
    for i in lista:
        r = r + i.to_bytes(1, 'big')
    return r

def pack_32bit(lista):
    return array.array('i', lista)

def nullbyte():
    null = 0
    return null.to_bytes(1,'big')

def put_size(packet):
    p = len(packet).to_bytes(2, 'big') + packet[2:]
    return p

def freeciv_bot(hostname, port, botname, version, password):
    server_address = (hostname, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        name = bytes(botname, 'ascii')
        freeciv = bytes(ser_version(version), 'ascii')        
        packer = pack_8bit([0, 0, PJOIN_REQ]) + name + nullbyte() + freeciv + nullbyte() + nullbyte() + pack_32bit([2,6,2])
    
        #send name to server
        sock.sendall(put_size(packer))
        r = 0
        while True:
            pong = 0
            #print("NR -------------------------------------:", r)
            block = get_block(sock)
            #print('Block says:'," ".join(["{:02}".format(x) for x in block]))  
            #print('Block says:', block.decode('ascii', 'ignore'))      
            if not block:
                break
            pong = process_jumbo(block)
            for rats in pong:
                if rats == PONG:
                    send_pong(sock)
                if rats == 6:
                    send_auth(sock, password)
           
            r = r + 1
    
    finally:
        print('closing socket')
        sock.close()
        

if __name__ == '__main__':
    parser = ArgumentParser(description='Freeciv Bot')
    parser.add_argument('hostname', nargs='?', default='linuxiuvat.de',
                         help='freeciv server hostname (default: %(default)s)')
    parser.add_argument('-p', type=int, metavar='port', default=5556,
                        help='TCP port number (default: %(default)s)')
    parser.add_argument('-n', type=str, metavar='botname',nargs='?', default="Python",
                         help='Bot name (default: %(default)s)')
    parser.add_argument('-password', type=str, metavar='password',nargs='?', default="",
                         help='Password (default: %(default)s)')
    parser.add_argument('-ver', type=int, metavar='server version', default=26,
                        help='Server version - 20 or 25 or 26 (default: %(default)s)')
    args = parser.parse_args()
    freeciv_bot(args.hostname, args.p, args.n, args.ver, args.password)
