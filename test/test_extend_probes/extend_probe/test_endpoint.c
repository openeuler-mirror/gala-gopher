#include <stdint.h>
#include <CUnit/Basic.h>

#include "test_endpoint.h"

static void TestEndpointBlackBox(void)
{
    /* start http_server node */
    int cmd_status;
    cmd_status = exec_cmd_test("echo \"ps -ef | grep 'http_server' | grep -v 'grep' | awk '{print \\$2}' | xargs -i kill -9 {}\" > tmp_cmd.sh");
    cmd_status = exec_cmd_test("echo \"python ../http_server.py > /dev/null 2>&1 &\" >> tmp_cmd.sh");
    /* start deploy http_server */
    cmd_status = exec_cmd_test("echo \"ps -ef | grep 'http_server' | grep -v 'grep' | awk '{print \\$2}'\" >> tmp_cmd.sh");
    char res[MAX_RETURN_INFO_LEN];
    res[0] = 0;
    cmd_status = exec_cmd_test_with_res("sh tmp_cmd.sh", res);
    if (cmd_status == -1) {
        fprintf(stderr, "restart http_server failed\n");
        return;
    }
    int proc_id = (int)atoi(res);
    if (proc_id < 0) {
        fprintf(stderr, "get an unsuitable proc_id: %d\n", proc_id);
        return;
    }
    /* curl put activate probe node */
    struct probe_s *probe = (struct probe_s *)malloc(sizeof(struct probe_s));
    if (probe == NULL) {
        return;
    }
    struct snooper_conf_s snooper_conf;
    snooper_conf.type = SNOOPER_CONF_PROC_ID;
    snooper_conf.conf.proc_id = proc_id;
    probe->snooper_confs[0] = &snooper_conf;
    struct ipc_body_s ipc_body;
    struct snooper_obj_s snooper_obj;
    probe->probe_type = PROBE_SOCKET;
    probe->probe_range_flags |= (u32)PROBE_RANGE_SOCKET_TCP;
    probe->probe_range_flags |= (u32)PROBE_RANGE_SOCKET_UDP;
    snooper_obj.obj.proc.proc_id = proc_id;
    snooper_obj.type = SNOOPER_OBJ_PROC;
    probe->snooper_objs[0] = &snooper_obj;
    probe->is_params_chg = IPC_FLAGS_PARAMS_CHG;
    probe->is_snooper_chg = IPC_FLAGS_SNOOPER_CHG;
    build_ipc_body(probe, &ipc_body);
    int msq_id = create_ipc_msg_queue(IPC_CREAT | IPC_EXCL);
    if (msq_id < 0) {
        fprintf(stderr, "Create ipc msg que failed.\n");
        goto err;
    }
    send_ipc_msg(msq_id, (long)probe->probe_type, &ipc_body);
    /* shutdown endpoint before send ipc info */
    cmd_status = exec_cmd_test("echo \"pkill endpoint\"> tmp_cmd.sh");
    cmd_status = exec_cmd_test_with_res("sh tmp_cmd.sh", res);
    if (cmd_status == -1) {
        fprintf(stderr, "shutdown endpoint failed.\n");
        goto err;
    }
    send_ipc_msg(msq_id, (long)probe->probe_type, &ipc_body);
    /* curl put to http_server */
    char cmd[] = "unset http_proxy && unset https_proxy";  // for copy easy.
    cmd_status = exec_cmd_test("echo \"chmod a+x endpoint && chmod 777 endpoint\" > tmp_cmd.sh");
    cmd_status = exec_cmd_test("echo \"./endpoint > endpoint_log.txt 2>&1 &\" > tmp_cmd.sh");
    cmd_status = exec_cmd_test("echo \"sleep 1\" >> tmp_cmd.sh");
    cmd_status = exec_cmd_test("echo \"unset http_proxy && unset https_proxy\" >> tmp_cmd.sh");
    cmd_status = exec_cmd_test("echo \"curl -X POST -d \\\"5\\\" http://localhost:8888/api\" >> tmp_cmd.sh");
    cmd_status = exec_cmd_test_with_res("sh tmp_cmd.sh", res);
    if (cmd_status == -1) {
        fprintf(stderr, "curl put to http_server failed.\n");
        goto err;
    }
    /* check result */
    char name_record[MAX_PROBE_ITEM][MAX_NAME_LEN];
    name_record[0][0] = 0;
    sleep(2);
    int log_status = CheckProbeLog("endpoint_log.txt", proc_id, name_record, "endpoint_tcp");
    int has_tcp_socket = CheckoutHaveSpeProbe(name_record, "endpoint_tcp");
    CU_ASSERT(has_tcp_socket)
    /* shutdown probe node */
    cmd_status = exec_cmd_test("pkill endpoint");
    /* shutdown http_server */
    cmd_status = exec_cmd_test("echo \"ps -ef | grep 'http_server' | grep -v 'grep' | awk '{print \\$2}' | xargs -i kill -9 {}\" > tmp_cmd.sh");
    res[0] = 0;
    cmd_status = exec_cmd_test_with_res("sh tmp_cmd.sh", res);
    if (cmd_status == -1) {
        fprintf(stderr, "Failed to shutdown http_server\n");
        goto err;
    }

err:
    clear_ipc_msg(probe->probe_type);
    free(probe);
    destroy_ipc_msg_queue(msq_id);
    fprintf(stderr, "\n\n[INFO] TestTcpBlackBox finished.\n\n");
}

void TestEndPointMain(CU_pSuite suite)
{
    CU_ADD_TEST(suite, TestEndpointBlackBox);
}