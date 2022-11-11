import sys
import time
import signal
import subprocess
import os
import getopt
import yaml
import psycopg2


PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # /opt/gala-gopher/
SELECT_PG_STAT_DATABASE = "select * from pg_stat_database where datname NOT IN ('template0','template1');"
g_metric = dict()
g_servers = []
g_period = 5


def get_tgid(port):
    # for host process
    command = "netstat -natp | grep LISTEN | grep gaussdb | grep %s | \
        awk -F ' ' 'NR ==1{print $7}' | awk -F '/' '{print $1}'" % (port)
    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (rawout, serr) = p.communicate(timeout=5)
    if len(rawout) != 0:
        return rawout.rstrip().decode()

    # for docker process
    command = "docker ps -q | xargs  docker inspect --format='{{.State.Pid}}, {{range $p, $conf := \
        .HostConfig.PortBindings}}{{$p}}{{end}}' | grep -w %s | awk -F ', ' 'NR ==1{print $1}'" % port
    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (rawout, serr) = p.communicate(timeout=5)
    if len(rawout) != 0:
        return rawout.rstrip().decode()
    return 0


def init_conns():
    global g_servers
    meta_path = os.path.join(PROJECT_PATH, "extend_probes/pg_stat_probe.conf")
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
                print("[pg_stat_probe]connect to %s:%s failed! %s" % (ip, port, repr(e)))
                sys.exit(1)
            print("[pg_stat_probe]connect to %s:%s success!"
                % (ip, port))
            cursor = conn.cursor()
            tgid = get_tgid(port)
            tgid_num = int(tgid)
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
            metric_key = server.tgid + '|' + str(line[0])
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


def init_param():
    global g_period
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "-d:")
    for opt, arg in opts:
        if opt in ["-d"]:
            g_period = int(arg)


if __name__ == "__main__":
    init_param()
    signal.signal(signal.SIGINT, signal_handler)
    init_conns()

    while True:
        time.sleep(g_period)
        get_metrics()

