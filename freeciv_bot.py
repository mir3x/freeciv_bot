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
import asyncio
import threading
import time
from argparse import ArgumentParser
from datetime import datetime

PJOIN_REQ = 4
PSTART = 0
JOINED = 333
JOIN_REPLY = 5
AUTH_REP = 7
PING = 88
PONG = 89
BEGIN_TURN = 128
TIMEOUT_INFO = 244
GAME_INFO = 16
PAGE_MSG = 110
PAGE_MSG_PART = 248
SEND_CHAT = 26

JUMBO_SIZE = 65535
COMPRESSION_BORDER = 16*1024+1
JUMBO_BORDER = 64*1024-COMPRESSION_BORDER-1
JUMBO_LEN = 4
HEADER_LEN = 2

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
int_struct = struct.Struct('!I')
float_struct = struct.Struct('!f')
double_struct = struct.Struct('!d')
char_struct = struct.Struct('!s')


send_from_now = False
speak = False


class race_db():
    def __init__(self):
        self.to_discord = []
        self.timer_target = -1
        self._lock = threading.Lock()

    def append_discord_message(self, message):
        with self._lock:
            self.to_discord.append(message)

    def pop_discord_message(self):
        with self._lock:
            return self.to_discord.pop(0)

    def discord_len(self):
        with self._lock:
            return len(self.to_discord)

    def get_timer_target(self):
        with self._lock:
            return self.timer_target

    def set_timer_target(self, timer):
        with self._lock:
            self.timer_target = timer


ricer = race_db()


def unpack_bool(fbytes):
    bbumbo = fbytes.read(1)
    (by, ) = bool_struct.unpack(bbumbo)
    return by


def unpack_string(fbytes):
    blocks = []
    while True:
        bbumbo = fbytes.read(1)
        if bbumbo == b'':
            break
        (by, ) = char_struct.unpack(bbumbo)
        if by in [b'\x00', b'\x03']:
            break
        blocks.append(by)
    return b''.join(blocks).decode('ascii')


# freeciv float is int/100, lol
def unpack_float(fbytes):
    bbumbo = fbytes.read(4)
    (by, ) = int_struct.unpack(bbumbo)
    by = by/100
    return by


def unpack_double(fbytes):
    bbumbo = fbytes.read(8)
    (by, ) = double_struct.unpack(bbumbo)
    return by


def unpack_int(fbytes):
    bbumbo = fbytes.read(4)
    (by, ) = struct.unpack('i', bbumbo)
    return by


def say_hello(msg):
    global sock_d
    msg = msg.rstrip('[/c]')
    msg = re.sub(r'\[c[^)]*\]', "", msg)
    msg = re.sub(">", " ", msg)
    msg = re.sub("<", " ", msg)
    print(msg)
    if rep := re.search(r"\w+(?=\s*has connected from)", msg):
        m = f"Hello {rep.group()} !"
        send_chat_msg(sock_d, m)
        send_chat_msg(sock_d, "WTF U DOING HERE???")
    else:
        print("WTF SAY HELLO")


def try_reply(msg):
    global speak

    if not speak:
        return

    if len(msg) < 3:
        return

    cases = {
        "has connected from": lambda: say_hello(msg)
    }

    for k in cases:
        if re.search(k, msg):
            return cases.get(k, lambda: "err")()


def process_packet(pkt):
    f = io.BytesIO(pkt)
    global send_from_now
    global ricer
    bumbo = f.read(3)

    (plen, pkt_type,) = prelogin_struct.unpack(bumbo)

    ret = 0

    if pkt_type == JOIN_REPLY:
        if unpack_bool(f) == 0:
            print("Cannot join to server")
        print("LOGIN MESSAGE: ", unpack_string(f))
        ret = JOINED
    if pkt_type == 6:
        print("AUTH REQ")
        ret = 6
    if pkt_type == 25:
        # 4 bytes header after postlogin crap?
        if (f.getbuffer().nbytes) > 4:
            f.read(1)

        dateTimeObj = datetime.now()
        s = unpack_string(f)
        if (bytes(s, 'ascii') != b'\x00'):
            # remove colors
            #s = re.sub(r'\[[^)]*\]', "",s)
            msg = f"{dateTimeObj.hour}:{dateTimeObj.minute}:{dateTimeObj.second} CHAT: {s}"
            print(msg)
            if (send_from_now):
                try_reply(msg)
                ricer.append_discord_message(msg)
    if pkt_type == TIMEOUT_INFO:
        x = f.read(1)
        if x == b'\x03':
            r = unpack_float(f)
            ricer.append_discord_message(r)
            print("TIMEOUT INFO", int(r))
            timer_t = time.perf_counter() + int(r)
            ricer.set_timer_target(timer_t)
    if pkt_type == PING:
        ret = PONG
    if pkt_type == BEGIN_TURN:
        ricer.append_discord_message("New turn")
        print("New turn")
    if pkt_type == PAGE_MSG:
        f.read(1)
        len_left = plen
        r = "*** REPORT ***"
        print(r)
        ricer.append_discord_message(r)

        r = unpack_string(f)
        ricer.append_discord_message(r)
        print(r)
        len_left -= len(r)
        if (len_left < 2):
            return ret
        r = unpack_string(f)
        ricer.append_discord_message(r)
        print(r)
    if pkt_type == PAGE_MSG_PART:
        f.read(1)
        print(unpack_string(f))

    return ret

# splits jumbo packet to single packets


def process_jumbo(jumbo):
    f = io.BytesIO(jumbo)

    x = 0
    rets = []
    while True:
        bumbo = f.read(3)
        if bumbo == b'':
            return rets
        blocks = [bumbo]
        (lenx, pkt_type,) = prelogin_struct.unpack(bumbo)
        r = f.read(lenx - 3)
        blocks.append(r)
        rrrr = b''.join(blocks)
        rets.append(process_packet(rrrr))
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

# gets whole packet with given size or jumbo packet


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
        bl = bl - JUMBO_LEN
        decompr = True
    elif block_length >= COMPRESSION_BORDER:
        decompr = True
        #data = recvall(sock, header_struct.size, False)
        bl = bl - COMPRESSION_BORDER
    block_length = bl
    y = recvall(sock, block_length - HEADER_LEN, decompr)
    blocks.append(y)
    return b''.join(blocks)

# sends packet to server


def put_block(sock, message):
    block_length = len(message)
    sock.send(header_struct.pack(block_length))
    sock.send(message)

# packet header with size of packet (except jumbo packet)


def get_header(sock):
    header = sock.recv(2)
    x = struct.unpack('!H', header)
    return x[0]

# new packet without header


def get_message(sock, len):
    sock.recv(len - 2)

# replies to server ping


def send_pong(sock):
    sock.sendall(put_size(pack_8bit([0, 0, PONG, ])))

# sends password to server


def send_auth(sock, password):
    auth = pack_8bit([0, 0, AUTH_REP, 1]) + \
        bytes(password, 'ascii') + nullbyte()
    print("Sending password")
    sock.sendall(put_size(auth))

# client attributes depending on server version


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
    return null.to_bytes(1, 'big')

# sets packet size in first 2 bytes


def put_size(packet):
    return len(packet).to_bytes(2, 'big') + packet[2:]


def send_chat_msg(sock, message):
    msg = pack_8bit([0, 0, SEND_CHAT, 1]) + \
        bytes(message, 'ascii') + nullbyte()
    sock.sendall(put_size(msg))


def freeciv_bot(hostname, port, botname, version, password):
    server_address = (hostname, port)
    global sock_d
    sock_d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('connecting to {} port {}'.format(*server_address))
    sock_d.connect(server_address)
    global send_from_now

    try:
        name = bytes(botname, 'ascii')
        freeciv = bytes(ser_version(version), 'ascii')
        # first 2 bytes are size of packet
        # 2,6,2 is just client version, works on any server
        packer = pack_8bit([0, 0, PJOIN_REQ]) + name + nullbyte() + \
            freeciv + nullbyte() + nullbyte() + pack_32bit([2, 6, 2])

        # send name to server
        sock_d.sendall(put_size(packer))
        r = 0
        while True:
            pong = 0
            #print("NR -------------------------------------:", r)
            block = get_block(sock_d)
            #print('Block says:'," ".join(["{:02}".format(x) for x in block]))
            #print('Block says:', block.decode('ascii', 'ignore'))
            if not block:
                break
            pong = process_jumbo(block)
            # jumbo is multipacket and could be many responses needed
            for rats in pong:
                if rats == PONG:
                    send_pong(sock_d)
                if rats == JOINED:
                    send_chat_msg(sock_d, "/detach")
                if rats == 6:
                    send_auth(sock_d, password)
            if (r > 3):
                send_from_now = True
            r = r + 1
    finally:
        print('closing socket')
        sock_d.close()


async def sleeping_dog():
    while True:
        await asyncio.sleep(1)


async def tcp_discord_send(message, once):
    global ricer
    global discord_id

    print('**********************************')
    while True:
        writer = 0
        try:
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', 9999)

            if ricer.discord_len():
                pmsg = ricer.pop_discord_message()
                msg = (discord_id + str(pmsg)).encode()
                print("ENCODED MSG:", msg)
                writer.write(msg)
            else:
                writer.write(discord_id.encode())
            await writer.drain()
            data = await reader.read(1024)
            if data not in [b'\x00', discord_id]:
                discord_request = data.decode('utf-8')
                if send_from_now and discord_request != b'\x00' and len(discord_request) > 1:
                    discord_request = discord_request.lstrip()
                    send_chat_msg(sock_d, discord_request)

            writer.close()
            await asyncio.sleep(1)
            if (once):
                break

        except:
            print("Unexpected error:", sys.exc_info()[0])

            if writer:
                writer.close()
            if (once):
                break
            await asyncio.sleep(1)


def loop_in_thread(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(tcp_discord_send('', False))


async def discord(discordID):
    global discord_id
    print("***Starting Discord Thread***")
    if (discordID != ""):
        discord_id = discordID
        discord_id = f"{discord_id}::"
        await tcp_discord_send('', False)
    print("***Ending Discord Thread***")


async def tc_timer():
    global ricer
    print("***Starting Timer Thread***")
    while True:
        s = time.perf_counter()
        x = ricer.get_timer_target()
        # there might be some big random value when connecting to server when game is not running
        if (int(x) != -1 and x < 9999999):
            x = x - s
            x = int(x)
            if x > 0 and x % 15 == 0:
                m = f"Time to new turn{x}"
                print(m)
                ricer.append_discord_message(m)
        await asyncio.sleep(1)


def thread_function(discordID, loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(tc_timer())
    loop.close()


def thread_function2(discordID, loop):
    asyncio.set_event_loop(loop)
    print("DISCORD ID")
    loop.run_until_complete(discord(discordID))
    loop.close()


def run_forest(hostname, port, botname, version, password, discordID, spik):
    global speak
    global send_from_now

    send_from_now = False
    speak = spik
    loop = asyncio.get_event_loop()
    x = threading.Thread(target=thread_function, args=(discordID, loop))
    x.start()
    loop = asyncio.new_event_loop()
    y = threading.Thread(target=thread_function2, args=(discordID, loop))
    y.start()
    freeciv_bot(hostname, port, botname, version, password)


if __name__ == '__main__':
    parser = ArgumentParser(description='Freeciv Bot')
    parser.add_argument('hostname', nargs='?', default='linuxiuvat.de',
                        help='freeciv server hostname (default: %(default)s)')
    parser.add_argument('-p', type=int, metavar='port', default=5556,
                        help='TCP port number (default: %(default)s)')
    parser.add_argument('-n', type=str, metavar='botname', nargs='?', default="Python",
                        help='Bot name (default: %(default)s)')
    parser.add_argument('-password', type=str, metavar='password', nargs='?', default="",
                        help='Password (default: %(default)s)')
    parser.add_argument('-ver', type=int, metavar='server version', default=26,
                        help='Server version - 20 or 25 or 26 (default: %(default)s)')
    parser.add_argument('-discordID', type=str, metavar='discordID', nargs='?', default='',
                        help='Password (default: %(default)s)')
    parser.add_argument('-speak', type=bool, metavar='speak', nargs='?', default='True',
                        help='Allow bot to speak (default: %(default)s)')
    args = parser.parse_args()
    run_forest(args.hostname, args.p, args.n, args.ver,
               args.password, args.discordID, args.speak)
