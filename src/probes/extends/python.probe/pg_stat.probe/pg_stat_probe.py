#!/usr/bin/python3
import sys
import time
import signal
import subprocess
import os
import getopt
import yaml
import psycopg2
import ipc

PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # /opt/gala-gopher/
SELECT_PG_STAT_DATABASE = "select * from pg_stat_database where datname NOT IN ('template0','template1');"
PG_PROCNAME = "gaussdb"
g_metric = dict()
g_servers = []
g_period = 5



def debug_log(msg: str):
    print("[DEBUG]: [pg_stat_probe]:" + msg)
    sys.stdout.flush()

def info_log(msg: str):
    print("[INFO]: [pg_stat_probe]:" + msg)
    sys.stdout.flush()

def error_log(msg: str):
    print("[ERROR]: [pg_stat_probe]:" + msg)
    sys.stdout.flush()

def get_tgid(port):
    tgid_num = 0

    # get all gaussdb tgid, delimited by space
    command = "pgrep -d \" \" -x %s" % PG_PROCNAME
    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (rawout, serr) = p.communicate(timeout=5)
    pg_pids = rawout.split()

    for pg_pid in pg_pids:
        tgid_num = int(pg_pid.decode())
        command = "nsenter -t %d -n netstat -ntpl 2>/dev/null | \
            grep \"%d/%s\" | grep \":%s\"" % (tgid_num, tgid_num, PG_PROCNAME, port)
        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (rawout, serr) = p.communicate(timeout=5)
        if len(rawout) != 0:
            return tgid_num

    return 0


def init_conns():
    global g_servers
    meta_path = os.path.join("/etc/gala-gopher/extend_probes/pg_stat_probe.conf")
    with open(meta_path, 'r') as f:
        conf = yaml.safe_load(f.read())
        for server in conf['servers']:
            ip = server['ip']
            port = server['port']
            dbname = server['dbname']
            user = server['user']
            password = server['password']
            try:
                conn = psycopg2.connect(
                    "host=%s port=%s dbname=%s user=%s password=%s connect_timeout=3"
                    % (ip, port, dbname, user, password))
            except Exception as e:
                error_log("connect to %s:%s failed! %s" % (ip, port, repr(e)))
                sys.exit(1)
            info_log("connect to %s:%s success!" % (ip, port))
            cursor = conn.cursor()
            tgid = get_tgid(port)
            g_servers.append(Connection(ip, port, tgid, conn, cursor))


def get_metrics():
    for server in g_servers:
        server.cursor.execute(SELECT_PG_STAT_DATABASE, None)
        lines = server.cursor.fetchall()
        server.conn.commit()
        for line in lines:
            '''
            the first four item of the line is:
            datid
            datname
            numbackends
            xact_commit
            '''
            metric_key = str(server.tgid) + '|' + str(line[0])
            metric_new_value = int(line[3])
            if metric_key in g_metric:
                metric_str = "|pg_tps|%s|POSTGRE|0|%s|%s|%s|" % (metric_key, server.ip, server.port, line[1])
                metric_rate = (metric_new_value - g_metric[metric_key]) / g_period
                print(metric_str + str(metric_rate) + "|")
                sys.stdout.flush()
            g_metric[metric_key] = metric_new_value


def stop_conns():
    for server in g_servers:
        if server.cursor:
            server.cursor.close()
        if server.conn:
            server.conn.close()
    sys.exit(0)


def signal_handler(signum, frame):
    stop_conns()


class Connection(object):
    def __init__(self, ip, port, tgid, conn, cursor):
        self.ip = ip
        self.port = port
        self.tgid = tgid
        self.conn = conn
        self.cursor = cursor


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    init_conns()
    ipc_body = ipc.IpcBody()

    msq_id = ipc.create_ipc_msg_queue(ipc.IPC_EXCL)
    if msq_id < 0:
        error_log("create ipc msg queue failed")
        sys.exit(1)

    while True:
        ret = ipc.recv_ipc_msg(msq_id, ipc.ProbeType.PROBE_GAUSS_SLI, ipc_body)
        if ret == 0:
            g_period = ipc_body.probe_param.period

        time.sleep(g_period)
        try:
            get_metrics()
        except Exception as e:
            error_log("get metrics failed. Err:" + str(e))
            stop_conns()

