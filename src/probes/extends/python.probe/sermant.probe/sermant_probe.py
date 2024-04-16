#!/usr/bin/python3
import os
import threading
import sys
import time
import signal
import requests
import ipc
from sermant_attach_utils import install_sermant, uninstall_sermant, uninstall_all, check_and_copy_sermant, \
    check_install_pid, check_metrics, print_to_log, check_and_uninstall_pid

# ensure the main jar location: {path}/agent/sermant-agent.jar
DEFAULT_SERMANT_ORIGINAL_PATH = "/opt/sermant/"
DEFAULT_REPORT_PERIOD = 5


def signal_handler(signum, frame):
    uninstall_all()
    sys.exit(0)


if __name__ == "__main__":
    period = DEFAULT_REPORT_PERIOD
    sermant_original_path = DEFAULT_SERMANT_ORIGINAL_PATH

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)

    ipc_body = ipc.IpcBody()
    s = requests.Session()

    msq_id = ipc.create_ipc_msg_queue(ipc.IPC_EXCL)
    if msq_id < 0:
        print_to_log("[sermant_probe] create ipc msg queue failed", "[ERROR]")
        sys.exit(-1)
    print_to_log("msq_id : " + str(msq_id), "[INFO]")

    thread_print_metrics = threading.Thread(target=check_metrics)
    thread_print_metrics.start()
    print_to_log("start thread read metrics file and print it.", "[INFO]")
    while True:
        ret = ipc.recv_ipc_msg(msq_id, ipc.ProbeType.PROBE_SERMANT, ipc_body)
        if ret == 0:
            if ipc_body.probe_flags & ipc.IPC_FLAGS_PARAMS_CHG or ipc_body.probe_flags == 0:
                if ipc_body.probe_param.period is not None and ipc_body.probe_param.period >= 0:
                    period = ipc_body.probe_param.period
                if ipc_body.probe_param.elf_path is not None and os.path.exists(ipc_body.probe_param.elf_path):
                    sermant_original_path = ipc_body.probe_param.elf_path
            if ipc_body.probe_flags & ipc.IPC_FLAGS_SNOOPER_CHG or ipc_body.probe_flags == 0:
                proc_list = ipc.get_snooper_proc_list(ipc_body)
                check_and_uninstall_pid(proc_list)
                for pid in proc_list:
                    print_to_log(" pid:" + str(pid))
                    if check_install_pid(pid):
                        # uncached pid, install sermant
                        if check_and_copy_sermant(pid, sermant_original_path):
                            result = install_sermant(pid)
                            print_to_log("install Sermant result: " + str(result))
                        else:
                            print_to_log("copy sermant to container failed", "[ERROR]")
            ipc.destroy_ipc_body(ipc_body)
        time.sleep(period)
