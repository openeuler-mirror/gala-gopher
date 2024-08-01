from ctypes import c_int, c_uint, c_char, c_char_p, c_long, pointer, Structure, Union, CDLL
from enum import IntEnum

DEV_NAME = 32
MAX_PATH_LEN = 512
PYSCOPE_SERVER_URL_LEN = 64
PATH_LEN = 256
SNOOPER_MAX = 100
IPC_EXCL = 0o2000 # copy from linux/ipc.h
IPC_FLAGS_SNOOPER_CHG = 0x00000001
IPC_FLAGS_PARAMS_CHG = 0x00000002

IPC_LIB = CDLL("/opt/gala-gopher/lib/ipc.so")

ProbeType = IntEnum('ProbeType', ('PROBE_BASEINFO', 'PROBE_VIRT', 'PROBE_FG', 'PROBE_L7', 'PROBE_TCP',\
    'PROBE_SOCKET', 'PROBE_IO', 'PROBE_PROC', 'PROBE_JVM', 'PROBE_POSTGRE_SLI', 'PROBE_GAUSS_SLI', \
    'PROBE_NGINX', 'PROBE_KAFKA', 'PROBE_TP', 'PROBE_HW', 'PROBE_KSLI', 'PROBE_CONTAINER', 'PROBE_SERMANT', 'PROBE_SLI', \
    'PROBE_FLOWTRACER', 'PROBE_TYPE_MAX'))
SnooperObjEnum = IntEnum('SnooperObjEnum', ('SNOOPER_OBJ_PROC', 'SNOOPER_OBJ_CON', 'SNOOPER_OBJ_MAX'), start = 0)

class ProbeParams(Structure):
    _fields_ = [
        ("period", c_uint),
        ("sample_period", c_uint),
        ("latency_thr", c_uint),
        ("offline_thr", c_uint),
        ("drops_count_thr", c_uint),
        ("kafka_port", c_uint),
        ("logs", c_char),
        ("metrics_flags", c_char),
        ("env_flags", c_char),
        ("support_ssl", c_char),
        ("res_percent_upper", c_char),
        ("res_percent_lower", c_char),
        ("continuous_sampling_flag", c_char),
        ("multi_instance_flag", c_char),
        ("native_stack_flag", c_char),
        ("cluster_ip_backend", c_char),
        ("target_dev", c_char * DEV_NAME),
        ("elf_path", c_char * MAX_PATH_LEN),
        ("l7_probe_proto_flags", c_uint),
        ("svg_period", c_uint),
        ("perf_sample_period", c_uint),
        ("pyroscope_server", c_char * PYSCOPE_SERVER_URL_LEN),
        ("svg_dir", c_char * PATH_LEN),
        ("flame_dir", c_char * PATH_LEN),
        ("cadvisor_port", c_uint),
    ]

class Proc(Structure):
    _fields_ = [
        ("proc_id", c_uint)
    ]

class SnooperConnInfo(Structure):
    _fields_ = [
        ("flags", c_uint),
        ("cpucg_inode", c_uint),
        ("con_id", c_char_p),
        ("container_name", c_char_p),
        ("libc_path", c_char_p),
        ("libssl_path", c_char_p),
        ("pod_id", c_char_p),
        ("pod_ip_str", c_char_p),
    ]

class MonitorObj(Union):
    _fields_ = [
        ("proc", Proc),
        ("con_info", SnooperConnInfo),
    ]

class SnooperObj(Structure):
     _fields_ = [
        ("type", c_uint),
        ("obj", MonitorObj)
    ]

class IpcBody(Structure):
    _fields_ = [
         ("probe_range_flags", c_uint),
         ("snooper_obj_num", c_uint),
         ("probe_flags", c_uint),
         ("probe_param", ProbeParams),
         ("snooper_objs", SnooperObj * SNOOPER_MAX)
    ]

def create_ipc_msg_queue(ipc_flag):
    IPC_LIB.create_ipc_msg_queue.restype = c_int
    return IPC_LIB.create_ipc_msg_queue(ipc_flag)

def recv_ipc_msg(msq_id, msg_type, ipc_body):
    _msq_id = c_int(msq_id)
    _msg_type = c_long(msg_type)
    _ipc_body = pointer(ipc_body)
    IPC_LIB.recv_ipc_msg.restype = c_int
    return IPC_LIB.recv_ipc_msg(_msq_id, _msg_type, _ipc_body)

def destroy_ipc_body(ipc_body):
    _ipc_body = pointer(ipc_body)
    return IPC_LIB.destroy_ipc_body(_ipc_body)

def get_snooper_proc_list(ipc_body):
    proc_list = []
    for i in range(ipc_body.snooper_obj_num):
        if ipc_body.snooper_objs[i].type == SnooperObjEnum.SNOOPER_OBJ_PROC and ipc_body.snooper_objs[i].obj.proc.proc_id != 0:
            proc_list.append(ipc_body.snooper_objs[i].obj.proc.proc_id)
    return proc_list
