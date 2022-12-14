from ctypes import cdll, c_uint, c_char, Structure, POINTER, pointer, create_string_buffer
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
CONTAINER_NAME_LEN = 64
CONTAINER_STATUS_RUNNING = 0
FILTER_BY_TASKPROBE = "task"
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # /opt/gala-gopher/
PATTERN = re.compile(r'/[a-z0-9]+')
COUNTER = "counter"
LABEL = "label"
g_meta = None
g_metric = dict()


class Proc(Structure):
    _fields_ = [
        ("proc_id", c_uint)
    ]

class ContainerInfo(Structure):
    _fields_ = [
        ("status", c_uint),
        ("abbrContainerId", c_char * CONTAINER_NAME_LEN)
    ]

class ContainerTbl(Structure):
    _fields_ = [
        ("num", c_uint),
        ("cs", POINTER(ContainerInfo))
    ]


class CadvisorParam(object):
    def __init__(self, port, period, filter_task_probe, filter_pid):
        self.port = port
        self.period = period
        self.filter_task_probe = filter_task_probe
        self.filter_pid = filter_pid


class ParamException(Exception):
    pass


def parse_filter_arg(argstr):
    filter_task_probe = False
    filter_pid = 0
    if argstr == FILTER_BY_TASKPROBE:
        filter_task_probe = True
    else:
        filter_pid = int(argstr)
    return filter_task_probe, filter_pid


def init_param():
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
        raise ParamException('[cadvisor_probe]no port param specified')
    return CadvisorParam(port, period, filter_task_probe, filter_pid)


def init_so():
    object_lib = None
    if params.filter_task_probe:
        object_lib_path = os.path.join(PROJECT_PATH, "lib/object.so")
        object_lib = cdll.LoadLibrary(object_lib_path)
        object_lib.obj_module_init()
        print("[cadvisor_probe]load object.so.")
    container_lib_path = os.path.join(PROJECT_PATH, "lib/container.so")
    container_lib = cdll.LoadLibrary(container_lib_path)
    print("[cadvisor_probe]load container.so.")
    return object_lib, container_lib


def offload_so(object_lib):
    if params.filter_task_probe:
        object_lib.obj_module_exit()
        print("[cadvisor_probe]offload object.so.")


def signal_handler(signum, frame):
    offload_so(object_lib)
    cadvisor_probe.stop_cadvisor()


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


class Probe:
    def __init__(self, object_lib, container_lib):
        self.object_lib = object_lib
        self.container_lib = container_lib

    def filter_container(self, container_id):
        if params.filter_task_probe:
            pid = pointer(c_uint(0))
            self.container_lib.get_container_pid(container_id, pid)
            ret = object_lib.is_proc_exist(pointer(Proc(pid[0])))
            return ret == 1

        if params.filter_pid != 0:
            pid = pointer(c_uint(0))
            self.container_lib.get_container_pid(container_id, pid)
            return pid == g_params.filter_pid

        return True


class BasicLabelProbe(Probe):
    def __init__(self, object_lib, container_lib):
        super().__init__(object_lib, container_lib)
        self.container_ids = set()

    def get_container_pid(self, container_id):
        pid = pointer(c_uint(0))
        self.container_lib.get_container_pid(container_id, pid)
        return str(pid[0])

    def get_container_name(self, container_id):
        name = create_string_buffer(CONTAINER_NAME_LEN)
        self.container_lib.get_container_name(container_id, name, CONTAINER_NAME_LEN)
        return str(name.value, encoding='utf-8')

    def get_container_cpucg_inode(self, container_id):
        inode = pointer(c_uint(0))
        self.container_lib.get_container_cpucg_inode(container_id, inode)
        return str(inode[0])

    def get_container_memcg_inode(self, container_id):
        inode = pointer(c_uint(0))
        self.container_lib.get_container_memcg_inode(container_id, inode)
        return str(inode[0])

    def get_container_pidcg_inode(self, container_id):
        inode = pointer(c_uint(0))
        self.container_lib.get_container_pidcg_inode(container_id, inode)
        return str(inode[0])

    def get_container_mntns_id(self, container_id):
        ns_id = pointer(c_uint(0))
        self.container_lib.get_container_mntns_id(container_id, ns_id)
        return str(ns_id[0])

    def get_container_netns_id(self, container_id):
        ns_id = pointer(c_uint(0))
        self.container_lib.get_container_netns_id(container_id, ns_id)
        return str(ns_id[0])

    def get_all_containers(self):
        self.container_ids.clear()

        self.container_lib.get_all_container.restype = POINTER(ContainerTbl)
        tbl_p = self.container_lib.get_all_container()

        for i in range(tbl_p.contents.num):
            if tbl_p.contents.cs[i].status != CONTAINER_STATUS_RUNNING:
                continue
            container_id = [chr(c) for c in tbl_p.contents.cs[i].abbrContainerId]
            container_id_str = ''.join(container_id)
            if not self.filter_container(container_id_str):
                continue
            self.container_ids.add(container_id_str)

    def get_basic_infos(self):
        global g_metric
        table_name = "container_basic"
        g_metric[table_name] = dict()

        self.get_all_containers()
        for container_id in self.container_ids:
            g_metric[table_name][container_id] = dict()
            g_metric[table_name][container_id]['container_id'] = container_id
            g_metric[table_name][container_id]['proc_id'] = self.get_container_pid(container_id)
            g_metric[table_name][container_id]['name'] = self.get_container_name(container_id)
            g_metric[table_name][container_id]['cpucg_inode'] = self.get_container_cpucg_inode(container_id)
            g_metric[table_name][container_id]['memcg_inode'] = self.get_container_memcg_inode(container_id)
            g_metric[table_name][container_id]['pidcg_inode'] = self.get_container_pidcg_inode(container_id)
            g_metric[table_name][container_id]['mnt_ns_id'] = self.get_container_mntns_id(container_id)
            g_metric[table_name][container_id]['net_ns_id'] = self.get_container_netns_id(container_id)
            g_metric[table_name][container_id]['value'] = '0'


class CadvisorProbe(Probe):
    def __init__(self, object_lib, container_lib, port_c):
        super().__init__(object_lib, container_lib)
        self.port = port_c
        self.pid = 0

    def get_cadvisor_port(self):
        p = subprocess.Popen("/usr/bin/netstat -natp | /usr/bin/grep cadvisor | /usr/bin/grep LISTEN | \
                            /usr/bin/awk  -F \":::\" '{print $2}'", stdout=subprocess.PIPE, shell=True)
        (rawout, serr) = p.communicate(timeout=5)
        if len(rawout) != 0:
            self.port = rawout.rstrip().decode()
            return True
        return False

    def start_cadvisor(self):
        p = subprocess.Popen("/usr/bin/ps -ef | /usr/bin/grep /usr/bin/cadvisor | /usr/bin/grep -v grep | \
                            /usr/bin/awk '{print $2}'", stdout=subprocess.PIPE, shell=True)
        (rawout, serr) = p.communicate(timeout=5)
        if len(rawout) != 0:
            self.pid = rawout.rstrip().decode()
            if self.get_cadvisor_port():
                print("[cadvisor_probe]cAdvisor has already been running at port %s." % self.port)
                return
            else:
                raise Exception('[cadvisor_probe]cAdvisor running but get info failed')
        ps = subprocess.Popen(["/usr/bin/cadvisor", "-port", str(self.port)], stdout=subprocess.PIPE, shell=False)
        self.pid = ps.pid
        print("[cadvisor_probe]cAdvisor started at port %s." % self.port)

    def stop_cadvisor(self):
        print("[cadvisor_probe]stop cAdvisor before exit.")
        subprocess.Popen(["/usr/bin/kill", "-9", str(self.pid)], stdout=subprocess.PIPE, shell=False)
        sys.exit(0)

    def find_2nd_index(self, stri, key):
        first = stri.index(key) + 1
        after_str = stri[first:]
        try:
            index = after_str.index(key)
        except Exception as e:
            index = len(after_str)
        return first + index

    def parse_container_id(self, metric_str):
        # find the last substring that satisfies PATTERN
        container_id = ""
        for sub_str in re.finditer(PATTERN, metric_str):
            container_id = sub_str.group(0)
        if len(container_id) - 1 != CONTAINER_NAME_LEN:
            return ""
        return container_id[1:CONTAINER_ABBR_ID_LEN + 1]
    
    def parse_metrics(self, raw_metrics):
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
                delimiter = self.find_2nd_index(line, "_")
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
                container_id = self.parse_container_id(metric_str.id)
                if container_id == "" or (not self.filter_container(container_id)):
                    continue

                hashed_metric_str = frozenset(metric_str.items())
                if hashed_metric_str not in g_metric[table_name]:
                    g_metric[table_name][hashed_metric_str] = metric_str
                    g_metric[table_name][hashed_metric_str]['container_id'] = container_id

                metric_name = line[line.index("_") + 1:line.index("{")]
                value = line[(line.index(" ") + 1):self.find_2nd_index(line, " ")]
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

    def get_metrics(self, session, port):
        r = session.get("http://localhost:%s/metrics" % port)
        r.raise_for_status()
        self.parse_metrics(r.text)


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


if __name__ == "__main__":
    params = init_param()
    object_lib, container_lib = init_so()
    cadvisor_running_flag = True
    cadvisor_probe = CadvisorProbe(object_lib, container_lib, params.port)
    try:
        cadvisor_probe.start_cadvisor()
    except ParamException as e:
        cadvisor_running_flag = False
    basic_probe = BasicLabelProbe(object_lib, container_lib)

    signal.signal(signal.SIGINT, signal_handler)
    convert_meta()

    s = requests.Session()
    while True:
        time.sleep(params.period)
        basic_probe.get_basic_infos()
        if cadvisor_running_flag:
            try:
                cadvisor_probe.get_metrics(s, params.port)
            except Exception as e:
                print("[cadvisor_probe]get metrics failed. Err: %s" % repr(e))
                s = requests.Session()
        print_metrics()
        clean_metrics()
