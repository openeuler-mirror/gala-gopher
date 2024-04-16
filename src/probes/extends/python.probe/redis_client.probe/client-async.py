#!/usr/bin/python3
import random
import time
import queue
import threading
import sys
import getopt
import socket
import signal
import os

import redis
from redis.connection import SocketBuffer

TABLE_NAME = "redis_client"

SUPPORT_CMDS = ["get", "set"]

SYM_STAR = b"*"
SYM_DOLLAR = b"$"
SYM_CRLF = b"\r\n"
SYM_EMPTY = b""

g_stop = False


def term_sig_hdl(signum, frame):
    global g_stop
    g_stop = True


def encode(value):
    if isinstance(value, bytes):
        return value
    elif isinstance(value, (int, float)):
        value = repr(value).encode()
    elif isinstance(value, str):
        value = value.encode()
    else:
        raise Exception("Data error")

    return value


def usage():
    print("Usage:")
    print("  python3 client-async.py [-h 127.0.0.1 [-p 6379 [-r 10000 [-d 5]]]]")
    print("Options:")
    print("  -h    redis server ip.")
    print("  -p    redis server port.")
    print("  -r    key range of redis command.")
    print("  -d    sample duration.")
    print("  -q    max send queue size.")
    print("  -t    test commands.")
    print("  -s    value length of redis command.")


def gen_random_str(length):
    base_str = 'abcdefg'
    base_str_len = len(base_str)
    rand_chars = [base_str[random.randint(0, base_str_len - 1)] for _ in range(length)]
    return ''.join(rand_chars)


class RedisClient:
    def __init__(self, host="127.0.0.1", port=6379, key_range=10000, period=5, max_queue_size=0, cmds=None,
                 cmd_val_len=1):
        self.host = host
        self.port = port
        self.key_range = key_range
        self.period = period * 1000 * 1000 * 1000
        self.max_queue_size = max_queue_size
        self.cmds = cmds
        self.cmd_val_len = cmd_val_len

        self.cmd_val = gen_random_str(cmd_val_len)
        self.cmds_queue = queue.Queue(self.max_queue_size)
        self.encode = encode
        self.sock = self.create_sock()
        self.buf = SocketBuffer(self.sock, 1024, 10)

        self.s_addr = self.sock.getsockname()[0]
        self.s_port = self.sock.getsockname()[1]
        self.d_addr = self.sock.getpeername()[0]
        self.d_port = self.sock.getpeername()[1]
        self.tgid = os.getpid()
        self.last_report = time.time_ns()
        self.samp_num = 0
        self.min_rtt = 0
        self.max_rtt = 0
        self.recent_rtt = 0
        self.recent_cmd = ''

    def create_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        return sock

    def init_db(self):
        r = redis.Redis(host=self.host, port=self.port, single_connection_client=True)
        pipe = r.pipeline()
        for k in range(self.key_range):
            pipe.set(str(k), self.cmd_val)
        pipe.execute()
        r.close()

    def send_cmd(self, cmd, *args):
        self.sock.sendall(self.pack_command(cmd, *args))
        self.cmds_queue.put([cmd, time.time_ns(), 0])

    # exp: "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"
    def pack_command(self, *args):
        output = []

        buff = SYM_EMPTY.join((SYM_STAR, str(len(args)).encode(), SYM_CRLF))
        output.append(buff)
        for arg in map(self.encode, args):
            buff = SYM_EMPTY.join(
                (
                    SYM_DOLLAR,
                    str(len(arg)).encode(),
                    SYM_CRLF,
                    arg,
                    SYM_CRLF,
                )
            )
            output.append(buff)

        return SYM_EMPTY.join(output)

    def recv_reply(self):
        resp = self.read_response()

        cmd = self.cmds_queue.get()
        ts = time.time_ns()
        cmd[2] = ts
        rtt = cmd[2] - cmd[1]
        if rtt < 0:
            rtt = 0
        if self.samp_num == 0:
            self.min_rtt = rtt
            self.max_rtt = rtt
        else:
            self.min_rtt = min(rtt, self.min_rtt)
            self.max_rtt = max(rtt, self.max_rtt)
        self.recent_rtt = rtt
        self.recent_cmd = cmd[0]
        self.samp_num = self.samp_num + 1
        self.cmds_queue.task_done()

        if self.need_report(ts):
            self.report(ts)

        return resp

    def reset_stats(self, ts):
        self.last_report = ts
        self.samp_num = 0
        self.min_rtt = 0
        self.max_rtt = 0
        self.recent_rtt = 0

    def read_response(self):
        raw = self.buf.readline()
        if not raw:
            raise Exception("Connection close")
        byte, response = raw[:1], raw[1:]
        if byte not in (b"-", b"+", b":", b"$"):
            raise Exception("Response error")
        if byte == b"$":
            length = int(response)
            if length == -1:
                return None
            response = self.buf.read(length)
        return response

    def need_report(self, ts):
        return ts > self.last_report + self.period

    def report(self, ts):
        print("|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|".format(
            TABLE_NAME,
            self.s_addr,
            self.s_port,
            self.d_addr,
            self.d_port,
            self.tgid,
            self.samp_num,
            self.min_rtt / 1000,
            self.max_rtt / 1000,
            self.recent_rtt / 1000,
            self.recent_cmd,
            self.cmds_queue.qsize(),
        ))
        sys.stdout.flush()
        self.reset_stats(ts)

    def close(self):
        self.sock.close()
        self.buf.close()


def gen_cmd_arg(cmd, redis_client):
    key_range = redis_client.key_range
    cmd = cmd.upper()
    if cmd == "GET":
        key = random.randint(0, key_range)
        return cmd, key
    elif cmd == "SET":
        key = random.randint(0, key_range)
        val = redis_client.cmd_val
        return cmd, key, val
    else:
        return None


def task_send_cmds(redis_client):
    print("===Start redis sending task...")
    global g_stop
    cmds = redis_client.cmds

    while True:
        if g_stop:
            break
        for cmd in cmds:
            cmd_arg = gen_cmd_arg(cmd, redis_client)
            if cmd_arg is None:
                break
            redis_client.send_cmd(*cmd_arg)

    print("===End redis sending task...")


def task_recv_replies(redis_client):
    print("===Start redis receiving task...")
    global g_stop

    while True:
        if g_stop:
            break
        try:
            redis_client.recv_reply()
        except Exception as ex:
            print(ex)
            break
    print("===End redis receiving task...")


def _check_rds_cmds(cmds):
    for cmd in cmds:
        if cmd not in SUPPORT_CMDS:
            print("Unsupported redis command {}".format(cmd))
            return False
    return True


def main():
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "h:p:r:d:q:t:s:")
    except:
        print("Params Error")
        return

    key_range = 10000
    host = "127.0.0.1"
    port = 6379
    period = 5
    max_queue_size = 0
    cmds = ["get"]
    cmd_val_len = 1
    for opt, arg in opts:
        if opt in ["-h"]:
            host = arg
        elif opt in ["-p"]:
            port = int(arg)
        elif opt in ["-k"]:
            key_range = int(arg)
        elif opt in ["-d"]:
            period = int(arg)
        elif opt in ["-q"]:
            max_queue_size = int(arg)
        elif opt in ["-t"]:
            cmds = str(arg).split(",")
            if not _check_rds_cmds(cmds):
                return
        elif opt in ["-s"]:
            cmd_val_len = int(arg)

    redis_client = RedisClient(host=host, port=port, key_range=key_range, period=period, max_queue_size=max_queue_size,
                               cmds=cmds, cmd_val_len=cmd_val_len)
    redis_client.init_db()

    thread1 = threading.Thread(target=task_send_cmds, args=(redis_client,))
    thread2 = threading.Thread(target=task_recv_replies, args=(redis_client,))
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()
    redis_client.close()


if __name__ == '__main__':
    usage()
    signal.signal(signal.SIGTERM, term_sig_hdl)
    signal.signal(signal.SIGINT, term_sig_hdl)
    main()
