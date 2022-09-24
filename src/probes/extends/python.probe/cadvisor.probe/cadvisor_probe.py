from ctypes import cdll, c_uint, Structure, pointer
import sys
import time
import signal
import subprocess
import os
import io
import re
import getopt
import requests
import libconf

DOCKER_LEN = 8
CONTAINER_ABBR_ID_LEN = 12
FILTER_BY_TASKPROBE = "task"
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # /opt/gala-gopher/
PATTERN = re.compile(r'/[a-z0-9]+')
COUNTER = "counter"
LABEL = "label"
g_meta = None
g_metric = dict()
g_object_lib = None
g_cadvisor_pid = None
g_params = None


class Proc_S(Structure):
    _fields_ = [
        ("proc_id", c_uint)
    ]


def init_so():
    global g_object_lib
    if g_params.filter_task_probe:
        object_lib_path = os.path.join(PROJECT_PATH, "lib/object.so")
        g_object_lib = cdll.LoadLibrary(object_lib_path)
        g_object_lib.obj_module_init()
        print("[cadvisor_probe]load object.so.")


def offload_so():
    global g_object_lib
    if g_params.filter_task_probe:
        g_object_lib.obj_module_exit()
        print("[cadvisor_probe]offload object.so.")


def get_container_pid(id):
    p = subprocess.Popen(["/usr/bin/docker", "inspect", str(id), "--format", "{{.State.Pid}}"], \
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    (rawout, serr) = p.communicate(timeout=5)
    return rawout.rstrip().decode("utf-8")


def filter_container(id):
    global g_object_lib

    if g_params.filter_task_probe:
        pid = int(get_container_pid(id))
        ret = g_object_lib.is_proc_exist(pointer(Proc_S(pid)))
        return ret == 1

    if g_params.filter_pid != 0:
        pid = int(get_container_pid(id))
        return pid == g_params.filter_pid

    return True


def convert_meta():
    '''
    Convert the meta file like the following format:
    g_meta[container_blkio] = 
    {
        'id': "key",
        'device': "label",
        'major': "label",
        'minor': "label",
        'operation': "label",
        'device_usage_total': "counter"
    }
    '''
    global g_meta
    meta_path = os.path.join(PROJECT_PATH, "extend_probes/cadvisor_probe.conf")
    with io.open(meta_path, encoding='utf-8') as f:
        meta = libconf.load(f)
        g_meta = dict()
        for measure in meta.measurements:
            g_meta[measure.table_name] = dict()
            for field in measure.fields:
                try:
                    g_meta[measure.table_name][field.name] = field.type
                except KeyError:
                    # main will catch the exception
                    raise


def find_2nd_index(stri, key):
    first = stri.index(key) + 1
    after_str = stri[first:]
    try:
        index = after_str.index(key)
    except Exception as e:
        index = len(after_str)
    return first + index


def parse_container_id(metric_str):
    # find the last substring that satisfies PATTERN
    container_id = ""
    for sub_str in re.finditer(PATTERN, metric_str):
        container_id = sub_str.group(0)
    if len(container_id) - 1 != 64: # len of container_id is 64
        return ""
    return container_id[1:CONTAINER_ABBR_ID_LEN + 1]


def parse_metrics(raw_metrics):
    '''
    Convert origin metric to the following format:
    before: 
        container_cpu_load_average_10s{id="/docker",image="redis",name="musing_archimedes"} 0 1658113125812
    after: g_metric['container_cpu'][hashed_metric_str] = {
        'id': '/docker',
        'image': 'redis',
        'name': 'musing_archimedes',
        'cpu_load_average_10s': 0,
        'container_id': 0
    }
    '''
    global g_metric

    for line in raw_metrics.splitlines():
        if line.startswith("container_"):
            delimiter = find_2nd_index(line, "_")
            table_name = line[:delimiter]
            if table_name not in g_meta:
                continue
            if table_name not in g_metric:
                g_metric[table_name] = dict()

            metric_str = libconf.loads(line[(line.index("{") + 1):line.index("} ")])
            if metric_str.id.startswith("/system.slice"):
                continue
            if metric_str.id.startswith("/user.slice"):
                continue
            container_id = parse_container_id(metric_str.id)
            if container_id == "" or (not filter_container(container_id)):
                continue

            hashed_metric_str = frozenset(metric_str.items())
            if hashed_metric_str not in g_metric[table_name]:
                g_metric[table_name][hashed_metric_str] = metric_str
                g_metric[table_name][hashed_metric_str]['container_id'] = container_id

            metric_name = line[line.index("_") + 1:line.index("{")]
            value = line[(line.index(" ") + 1):find_2nd_index(line, " ")]
            try:
                if g_meta[table_name][metric_name] == COUNTER:
                    if metric_name in g_metric[table_name][hashed_metric_str]:
                        g_metric[table_name][hashed_metric_str][metric_name][1] = float(value)
                    else:
                        g_metric[table_name][hashed_metric_str][metric_name] = [0, float(value)]
                else:
                    g_metric[table_name][hashed_metric_str][metric_name] = value
            except KeyError:
                # main will catch the exception
                raise


def print_metrics():
    '''
    Convert metric to the following format:
    |container_blkio|c903e934945006f82cd81ce4131a0b719984d10e7ca7bec3f6c024193d86aa85|/dev/dm-0|253|0|Async|0|
    '''
    global g_metric
    global g_meta
    for table, records in g_metric.items():
        if table not in g_meta:
            continue
        for record in records.values():
            s = "|" + table + "|"
            if table in g_meta:
                for field_name, field_type in g_meta[table].items():
                    if field_name not in record:
                        if field_type == LABEL:
                            value = "NA"
                        else:
                            value = ""
                    else:
                        if field_type == COUNTER:
                            value = str(record[field_name][1] - record[field_name][0])
                            record[field_name][0] = record[field_name][1]
                        else:
                            value = record[field_name]
                    s = s + value + "|"
                print(s)
                sys.stdout.flush()


def clean_metrics():
    pass
    # Clean up containers that don't exist 


class CadvisorProbe(object):
    def __init__(self, port_c):
        self.port = port_c

    def get_cadvisor_port(self):
        p = subprocess.Popen("/usr/bin/netstat -natp | /usr/bin/grep cadvisor | /usr/bin/grep LISTEN | \
                            /usr/bin/awk  -F \":::\" '{print $2}'", stdout=subprocess.PIPE, shell=True)
        (rawout, serr) = p.communicate(timeout=5)
        if len(rawout) != 0:
            self.port = rawout.rstrip().decode()
            return True
        return False

    def start_cadvisor(self):
        global g_cadvisor_pid
        p = subprocess.Popen("/usr/bin/ps -ef | /usr/bin/grep /usr/bin/cadvisor | /usr/bin/grep -v grep | \
                            /usr/bin/awk '{print $2}'", stdout=subprocess.PIPE, shell=True)
        (rawout, serr) = p.communicate(timeout=5)
        if len(rawout) != 0:
            g_cadvisor_pid = rawout.rstrip().decode()
            if self.get_cadvisor_port():
                print("[cadvisor_probe]cAdvisor has already been running at port %s." % self.port)
                return
            else:
                raise Exception('[cadvisor_probe]cAdvisor running but get info failed')
        ps = subprocess.Popen(["/usr/bin/cadvisor", "-port", str(self.port)], stdout=subprocess.PIPE, shell=False)
        g_cadvisor_pid = ps.pid
        print("[cadvisor_probe]cAdvisor started at port %s." % self.port)


def get_metrics(session, port):
    r = session.get("http://localhost:%s/metrics" % port)
    r.raise_for_status()

    parse_metrics(r.text)
    print_metrics()
    clean_metrics()


def stop_cadvisor():
    print("[cadvisor_probe]stop cAdvisor before exit.")
    subprocess.Popen(["/usr/bin/kill", "-9", str(g_cadvisor_pid)], stdout=subprocess.PIPE, shell=False)
    sys.exit(0)


def signal_handler(signum, frame):
    offload_so()
    stop_cadvisor()


class CadvisorParam(object):
    def __init__(self, port, period, filter_task_probe, filter_pid):
        self.port = port
        self.period = period
        self.filter_task_probe = filter_task_probe
        self.filter_pid = filter_pid


def parse_filter_arg(argstr):
    filter_task_probe = False
    filter_pid = 0
    if argstr == FILTER_BY_TASKPROBE:
        filter_task_probe = True
    else:
        filter_pid = int(argstr)
    return filter_task_probe, filter_pid


def init_param():
    global g_params
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "-p:-d:-F:")
    port = 0
    period = 5
    filter_task_probe = False
    filter_pid = 0
    for opt, arg in opts:
        if opt in ["-p"]:
            port = int(arg)
        elif opt in ["-d"]:
            period = int(arg)
        elif opt in ["-F"]:
            filter_task_probe, filter_pid = parse_filter_arg(arg)
    if port == 0:
        raise Exception('[cadvisor_probe]no port param specified')
    g_params = CadvisorParam(port, period, filter_task_probe, filter_pid)


if __name__ == "__main__":
    init_param()
    init_so()
    probe = CadvisorProbe(g_params.port)
    probe.start_cadvisor()
    signal.signal(signal.SIGINT, signal_handler)
    convert_meta()

    s = requests.Session()
    while True:
        time.sleep(g_params.period)
        try:
            get_metrics(s, g_params.port)
        except Exception as e:
            print("[cadvisor_probe]get metrics failed. Err: %s" % repr(e))
            s = requests.Session()
