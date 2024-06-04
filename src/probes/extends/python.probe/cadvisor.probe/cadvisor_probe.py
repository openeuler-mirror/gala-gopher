#!/usr/bin/python3
from ctypes import cdll, c_uint, c_char, Structure, POINTER, pointer, create_string_buffer
import sys
import time
import signal
import subprocess
import os
import io
import requests
import json
import re
import ipc

CONTAINER_ID_LEN = 64
CGROUP_PATH_LEN = 256
DEFAULT_CADVISOR_PORT = 8083
DEFAULT_REPORT_PERIOD = 60
DISABLE_METRICS_OPTION = "-disable_metrics=udp,cpu_topology,resctrl,tcp,advtcp,sched,hugetlb,referenced_memory"
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # /opt/gala-gopher/
COUNTER = "counter"
LABEL = "label"
KEY = "key"
CPUSET = "cpuset"
g_meta = None
g_metric = dict()

def debug_log(msg: str):
    print("[DEBUG]: [CADVISOR_PROBE]:" + msg)
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())

def info_log(msg: str):
    print("[INFO]: [CADVISOR_PROBE]:" + msg)
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())

def error_log(msg: str):
    print("[ERROR]: [CADVISOR_PROBE]:" + msg)
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())

class ParamException(Exception):
    pass

def init_so():
    container_lib_path = os.path.join(PROJECT_PATH, "lib/container.so")
    container_lib = cdll.LoadLibrary(container_lib_path)
    info_log("load container.so.")
    return container_lib

def signal_handler(signum, frame):
    cadvisor_probe.stop_cadvisor()
    sys.exit(0)

def convert_meta():
    '''
    Convert the meta file like the following format:
    g_meta[cpu_system_seconds_total] =
    {
        'id': "key",
        'cpu': "label",
        'cpu_system_seconds_total': "counter"
    }
    '''
    global g_meta
    meta_path = os.path.join("/etc/gala-gopher/extend_probes/cadvisor_probe.conf")
    with io.open(meta_path, encoding='utf-8') as f:
        meta = json.load(f)
        g_meta = dict()
        for measure in meta.get("measurements"):
            g_meta[measure.get("table_name")] = dict()
            for field in measure.get("fields"):
                try:
                    g_meta[measure.get("table_name")][field.get("name")] = field.get("type")
                except KeyError:
                    # main will catch the exception
                    raise

def get_meta_label_list():
    global g_meta
    str = ''
    for key1 in g_meta.keys():
        for key2 in g_meta[key1].keys():
            if g_meta[key1][key2] == LABEL:
                str = str + key2 + ','
    return str[:-1]

class ContainerUtils():
    def __init__(self, container_lib):
        self.container_lib = container_lib

    def get_container_id_by_pid(self, pid):
        container_id = create_string_buffer(CONTAINER_ID_LEN)
        self.container_lib.get_container_id_by_pid_cpuset(str(pid).encode(), container_id, CONTAINER_ID_LEN)
        return str(container_id.value, encoding='utf-8')

    def get_container_cgroup_path_by_pid(self, pid):
        cgroup_path = create_string_buffer(CGROUP_PATH_LEN)
        self.container_lib.get_cgp_dir_by_pid(pid, str.encode(CPUSET), cgroup_path, CGROUP_PATH_LEN)
        return str(cgroup_path.value, encoding='utf-8')

class CadvisorProbe():
    def __init__(self, port_c):
        self.port = port_c
        self.pid = 0
        self.cgroup_path_map = dict()

    def set_cgroup_path_map(self, map):
        self.cgroup_path_map = map

    def get_cadvisor_port(self):
        p = subprocess.Popen("/usr/bin/netstat -nltp | /usr/bin/grep cadvisor | \
                            /usr/bin/awk  -F \":::\" '{print $2}'", stdout=subprocess.PIPE, shell=True)
        try:
            (rawout, serr) = p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            return False

        if len(rawout) != 0:
            self.port = rawout.rstrip().decode()
            return True
        return False

    def start_cadvisor(self, period):
        p = subprocess.Popen("which cadvisor", stdout=subprocess.PIPE, shell=True)
        p.communicate(timeout=5)
        if p.returncode != 0:
            raise Exception('cAdvisor not installed')
        p = subprocess.Popen("/usr/bin/ps -ef | /usr/bin/grep /usr/bin/cadvisor | /usr/bin/grep -v grep | \
                            /usr/bin/awk '{print $2}'", stdout=subprocess.PIPE, shell=True)
        try:
            (rawout, serr) = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            error_log("Failed to get cAdvisor running state")
            sys.exit(0)

        if len(rawout) != 0:
            self.pid = rawout.rstrip().decode()
            if self.get_cadvisor_port():
                info_log("cAdvisor has already been running at port %s." % self.port)
                return
            else:
                raise Exception('cAdvisor running but get info failed')
        whitelist_label = "-whitelisted_container_labels=" + get_meta_label_list()
        interval = "--housekeeping_interval="+ str(period) + "s"
        ps = subprocess.Popen(["/usr/bin/cadvisor", "-port", str(self.port),\
            "--store_container_labels=false", interval, whitelist_label,\
            DISABLE_METRICS_OPTION],\
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
        try:
            ps.wait(timeout=3)
        except subprocess.TimeoutExpired:
            info_log("cAdvisor started at port %s." % self.port)
        else:
            error_log("cAdvisor started at port %s failed. retcode: %d" % (self.port, ps.returncode))
            sys.exit(0)
        self.pid = ps.pid

    def stop_cadvisor(self):
        info_log("stop cAdvisor before exit.")
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

    def parse_metrics(self, raw_metrics):
        '''
        Convert origin metric to the following format:
        before:
            cpu_usage_seconds_total{id="/docker",image="redis", cpu="cpu01", name="musing_archimedes"} 0 1658113125812
        after: g_metric['container_cpu'][container_id]['cpu_usage_seconds_total'] = {
                   "cpu01": {
                        [0, 0]
                    }
               }
        '''
        global g_metric

        for line in raw_metrics.splitlines():
            if line.startswith("container_"):
                delimiter = self.find_2nd_index(line, "_")
                table_name = line[:delimiter]
                if table_name not in g_meta:
                    continue
                metric_name = line[(line.index("_") + 1):line.index("{")]
                if metric_name not in g_meta[table_name]:
                    continue
                if table_name not in g_metric:
                    g_metric[table_name] = dict()

                metric_str = line[line.index("{"):line.index("} ")+1]
                metric_dict = json.loads(re.sub(r'(\w+)=', r'"\1":', metric_str))
                # cadvisor metric id is cgroup path of container
                if metric_dict.get("id") not in self.cgroup_path_map.keys():
                    continue

                label_key= ''
                for field_name, field_type in g_meta[table_name].items():
                    if field_type == LABEL and field_name in metric_dict:
                        label_key += "_" + metric_dict[field_name]

                if label_key == '':
                    label_key = LABEL

                container_id = self.cgroup_path_map[metric_dict.get("id")]
                if container_id not in g_metric[table_name]:
                    g_metric[table_name][container_id] = dict()

                if metric_name not in g_metric[table_name][container_id]:
                    g_metric[table_name][container_id][metric_name] = dict()

                value_start_index = line.rfind("}") + 1
                value_end_index = value_start_index + self.find_2nd_index(line[value_start_index:], " ")
                value = line[value_start_index:value_end_index]

                try:
                    if g_meta[table_name][metric_name] == COUNTER:
                        if label_key in g_metric[table_name][container_id][metric_name]:
                            g_metric[table_name][container_id][metric_name][label_key][1] = float(value)
                        else:
                            g_metric[table_name][container_id][metric_name][label_key] = [float(value), float(value)]
                    else:
                        g_metric[table_name][container_id][metric_name][label_key] = float(value)
                except KeyError:
                    # main will catch the exception
                    raise

    def get_metrics(self, session, port):
        r = session.get("http://localhost:%s/metrics" % port)
        r.raise_for_status()
        self.parse_metrics(r.text)

    def change_cadvisor_port(self, port, period):
        if self.get_cadvisor_port() and self.port == port:
            return True
        self.stop_cadvisor()
        self.port = port
        try:
            cadvisor_probe.start_cadvisor(period)
        except Exception as e:
            error_log("start cadvisor failed. Err: %s" % repr(e))
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
        for key, record in records.items():
            s = "|" + table + "|"
            for field_name, field_type in g_meta[table].items():
                value = 0
                if field_type == LABEL:
                    continue

                if field_type == KEY:
                    value = key
                    s += value + "|"
                    continue

                if field_name not in record:
                    value = ""
                else:
                    for item in record[field_name].values():
                        if field_type == COUNTER:
                            if item[1] > item[0]:
                                value += item[1] - item[0]
                            else:
                                value += 0
                            item[0] = item[1]
                        else:
                            value += item
                s = s + str(value) + "|"
            print(s)
            try:
                sys.stdout.flush()
            except BrokenPipeError:
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())


def clean_metrics():
    pass
    # Clean up containers that don't exist

def reset_g_metric():
    global g_metric
    g_metric = {}


if __name__ == "__main__":
    cadvisor_port = DEFAULT_CADVISOR_PORT
    period = DEFAULT_REPORT_PERIOD
    cadvisor_running_flag = False

    convert_meta()
    container_lib = init_so()
    signal.signal(signal.SIGINT, signal_handler)
    containerUtils = ContainerUtils(container_lib)
    ipc_body = ipc.IpcBody()
    s = requests.Session()

    msq_id = ipc.create_ipc_msg_queue(ipc.IPC_EXCL)
    if msq_id < 0:
        error_log("create ipc msg queue failed")
        sys.exit(-1)

    cadvisor_probe = CadvisorProbe(cadvisor_port)

    while True:
        ret = ipc.recv_ipc_msg(msq_id, ipc.ProbeType.PROBE_CONTAINER, ipc_body)
        if ret == 0:
            if ipc_body.probe_flags & ipc.IPC_FLAGS_PARAMS_CHG or ipc_body.probe_flags == 0 or not cadvisor_running_flag:
                period = ipc_body.probe_param.period
                if cadvisor_probe.change_cadvisor_port(ipc_body.probe_param.cadvisor_port, period):
                    cadvisor_running_flag = True
                    cadvisor_port = ipc_body.probe_param.cadvisor_port
                else:
                    cadvisor_running_flag = False

            if ipc_body.probe_flags & ipc.IPC_FLAGS_SNOOPER_CHG or ipc_body.probe_flags == 0:
                cgroup_path_map = {}
                proc_list = ipc.get_snooper_proc_list(ipc_body)
                for pid in proc_list:
                    container_id = containerUtils.get_container_id_by_pid(pid)
                    if container_id == '':
                        continue
                    cgroup_path = containerUtils.get_container_cgroup_path_by_pid(pid)
                    cgroup_path_map[cgroup_path] = container_id
                cadvisor_probe.set_cgroup_path_map(cgroup_path_map)
                reset_g_metric()
            ipc.destroy_ipc_body(ipc_body)

        if cadvisor_running_flag and cadvisor_probe.cgroup_path_map:
            try:
                cadvisor_probe.get_metrics(s, cadvisor_port)
            except Exception as e:
                debug_log("get metrics failed. Err: %s" % repr(e))
                s = requests.Session()
        print_metrics()
        clean_metrics()
        time.sleep(period)
