#!/usr/bin/python3
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
import ipc

DOCKER_LEN = 8
CONTAINER_ABBR_ID_LEN = 12
CONTAINER_NAME_LEN = 64
CONTAINER_ID_LEN = 64
CONTAINER_STATUS_RUNNING = 0
DEFAULT_CADVISOR_PORT = 8080
DEFAULT_REPORT_PERIOD = 5
FILTER_BY_TASKPROBE = "task"
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # /opt/gala-gopher/
PATTERN = re.compile(r'[/-][a-z0-9]+')
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
        ("abbrContainerId", c_char * (CONTAINER_NAME_LEN + 1))
    ]

class ContainerTbl(Structure):
    _fields_ = [
        ("num", c_uint),
        ("cs", POINTER(ContainerInfo))
    ]

class ParamException(Exception):
    pass

def init_so():
    container_lib_path = os.path.join(PROJECT_PATH, "lib/container.so")
    container_lib = cdll.LoadLibrary(container_lib_path)
    print("[cadvisor_probe]load container.so.")
    return container_lib

def signal_handler(signum, frame):
    cadvisor_probe.stop_cadvisor()
    sys.exit(0)

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
    meta_path = os.path.join("/etc/gala-gopher/extend_probes/cadvisor_probe.conf")
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

def get_meta_label_list():
    global g_meta
    str = ''
    for key1 in g_meta.keys():
        if key1 == 'container_basic':
            continue
        for key2 in g_meta[key1].keys():
            if g_meta[key1][key2] == LABEL:
                str = str + key2 + ','
    return str[:-1]


class Probe:
    def __init__(self, container_lib, container_list):
        self.container_lib = container_lib
        self.container_list = container_list

    def filter_container(self, container_id):
        if container_id in self.container_list:
            return True
        else:
            return False

    def set_container_list(self, container_list):
        self.container_list = container_list


class BasicLabelProbe(Probe):
    def __init__(self, container_lib):
        super().__init__(container_lib, [])
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

    def get_container_id_by_pid(self, pid):
        container_id = create_string_buffer(CONTAINER_ID_LEN)
        self.container_lib.get_container_id_by_pid(pid, container_id, CONTAINER_ID_LEN)
        return str(container_id.value, encoding='utf-8')

    def get_all_containers(self):
        self.container_ids.clear()

        self.container_lib.get_all_container.restype = POINTER(ContainerTbl)
        tbl_p = self.container_lib.get_all_container()

        if not tbl_p:
            print("[cadvisor_probe] no active containers in system")
            return 0

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
            # ctype c_char_p is bytes in python3, convert str to bytes
            container_id_bytes = str.encode(container_id)
            g_metric[table_name][container_id] = dict()
            g_metric[table_name][container_id]['container_id'] = container_id
            g_metric[table_name][container_id]['proc_id'] = self.get_container_pid(container_id_bytes)
            g_metric[table_name][container_id]['name'] = self.get_container_name(container_id_bytes)
            g_metric[table_name][container_id]['cpucg_inode'] = self.get_container_cpucg_inode(container_id_bytes)
            g_metric[table_name][container_id]['memcg_inode'] = self.get_container_memcg_inode(container_id_bytes)
            g_metric[table_name][container_id]['pidcg_inode'] = self.get_container_pidcg_inode(container_id_bytes)
            g_metric[table_name][container_id]['mnt_ns_id'] = self.get_container_mntns_id(container_id_bytes)
            g_metric[table_name][container_id]['net_ns_id'] = self.get_container_netns_id(container_id_bytes)
            g_metric[table_name][container_id]['value'] = '0'


class CadvisorProbe(Probe):
    def __init__(self, container_lib, port_c):
        super().__init__(container_lib, [])
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
        p = subprocess.Popen("which cadvisor", stdout=subprocess.PIPE, shell=True)
        p.communicate(timeout=5)
        if p.returncode != 0:
            raise Exception('[cadvisor_probe] cAdvisor not installed')
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
        whitelist_label = "-whitelisted_container_labels=" + get_meta_label_list()
        ps = subprocess.Popen(["/usr/bin/cadvisor", "-port", str(self.port),\
            "--store_container_labels=false", whitelist_label\
            ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
        self.pid = ps.pid
        print("[cadvisor_probe]cAdvisor started at port %s." % self.port)

    def stop_cadvisor(self):
        print("[cadvisor_probe]stop cAdvisor before exit.")
        if self.pid != 0:
            subprocess.Popen(["/usr/bin/kill", "-9", str(self.pid)], stdout=subprocess.PIPE, shell=False)

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
        if len(container_id) - 1 < CONTAINER_ABBR_ID_LEN:
            return ""
        return container_id[1:CONTAINER_ABBR_ID_LEN + 1]
    
    def parse_metrics(self, raw_metrics):
        '''
        Convert origin metric to the following format:
        before: 
            container_cpu_load_average_10s{id="/docker",image="redis",name="musing_archimedes"} 0 1658113125812
        after: g_metric['container_cpu'][container_id] = {
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
                metric_name = line[line.index("_") + 1:line.index("{")]
                if metric_name not in g_meta[table_name]:
                    continue
                if table_name not in g_metric:
                    g_metric[table_name] = dict()

                metric_str = libconf.loads(line[(line.index("{") + 1):line.index("} ")])
                '''
                docker use systemd as cgroupfs in k8s, cadvisor metric id like:
                {id="/system.slice/docker-1044qbdeeedqdff...scope"}
                normal metric_id like:
                {id="/docker/1044qbdeeedqdff..."}
                '''
                if metric_str.id.startswith("/system.slice") and 'docker-' not in metric_str.id:
                    continue
                if metric_str.id.startswith("/user.slice"):
                    continue
                container_id = self.parse_container_id(metric_str.id)
                if container_id == "" or (not self.filter_container(container_id)):
                    continue

                if container_id not in g_metric[table_name]:
                    g_metric[table_name][container_id] = dict()
                    g_metric[table_name][container_id]['container_id'] = container_id

                value_start_index = line.rfind("}") + 1
                value_end_index = value_start_index + self.find_2nd_index(line[value_start_index:], " ")
                value = line[value_start_index:value_end_index]
                try:
                    if g_meta[table_name][metric_name] == COUNTER:
                        if metric_name in g_metric[table_name][container_id]:
                            g_metric[table_name][container_id][metric_name][1] = float(value)
                        else:
                            g_metric[table_name][container_id][metric_name] = [0, float(value)]
                    else:
                        g_metric[table_name][container_id][metric_name] = value
                except KeyError:
                    # main will catch the exception
                    raise

    def get_metrics(self, session, port):
        r = session.get("http://localhost:%s/metrics" % port)
        r.raise_for_status()
        self.parse_metrics(r.text)

    def change_cadvisor_port(self, port):
        if self.get_cadvisor_port() and self.port == port:
            return True
        self.stop_cadvisor()
        self.port = port
        try:
            cadvisor_probe.start_cadvisor()
        except Exception as e:
            print(e)
            return False
        return True

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
                            if record[field_name][1] > record[field_name][0]:
                                value = str(record[field_name][1] - record[field_name][0])
                            else:
                                value = "0"
                            record[field_name][0] = record[field_name][1]
                        else:
                            value = record[field_name]
                    s = s + value + "|"
                print(s)
                sys.stdout.flush()


def clean_metrics():
    pass
    # Clean up containers that don't exist

def reset_g_metric():
    global g_metric
    g_metric = {}


if __name__ == "__main__":
    cadvisor_port = DEFAULT_CADVISOR_PORT
    period = DEFAULT_REPORT_PERIOD
    cadvisor_running_flag = True

    convert_meta()
    container_lib = init_so()
    signal.signal(signal.SIGINT, signal_handler)
    basic_probe = BasicLabelProbe(container_lib)
    ipc_body = ipc.IpcBody()
    s = requests.Session()

    msq_id = ipc.create_ipc_msg_queue(ipc.IPC_EXCL)
    if msq_id < 0:
        print("[cadvisor_probe] create ipc msg queue failed")
        sys.exit(-1)

    cadvisor_probe = CadvisorProbe(container_lib, cadvisor_port)
    try:
        cadvisor_probe.start_cadvisor()
    except Exception as e:
        print(e)
        cadvisor_running_flag = False

    while True:
        ret = ipc.recv_ipc_msg(msq_id, ipc.ProbeType.PROBE_CONTAINER, ipc_body)
        if ret == 0:
            if ipc_body.probe_flags & ipc.IPC_FLAGS_PARAMS_CHG or ipc_body.probe_flags == 0:
                period = ipc_body.probe_param.period
                if cadvisor_probe.change_cadvisor_port(ipc_body.probe_param.cadvisor_port):
                    cadvisor_running_flag = True
                    cadvisor_port = ipc_body.probe_param.cadvisor_port
                else:
                    cadvisor_running_flag = False

            if ipc_body.probe_flags & ipc.IPC_FLAGS_SNOOPER_CHG or ipc_body.probe_flags == 0:
                container_list = []
                proc_list = ipc.get_snooper_proc_list(ipc_body)
                for pid in proc_list:
                    container_id = basic_probe.get_container_id_by_pid(pid)
                    container_list.append(container_id)
                basic_probe.set_container_list(container_list)
                cadvisor_probe.set_container_list(container_list)
                reset_g_metric()
                basic_probe.get_basic_infos()
            ipc.destroy_ipc_body(ipc_body)

        if cadvisor_running_flag:
            try:
                cadvisor_probe.get_metrics(s, cadvisor_port)
            except Exception as e:
                print("[cadvisor_probe]get metrics failed. Err: %s" % repr(e))
                s = requests.Session()
        print_metrics()
        clean_metrics()
        time.sleep(period)
