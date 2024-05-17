#ifndef COMMON_INTERFACE_H
#define COMMON_INTERFACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <signal.h>
#include <errno.h>

#include "common.h"
#include "ipc.h"
#include "probe_mng.h"
#include "snooper.h"

#define MAX_RETURN_INFO_LEN 256
#define MAX_PROCESS_RES_LEN 1024
#define EXEC_MAX 256
#define DEFAULT_USER_ID 0xffffffff
#define ERROR_SETUID (-10)
#define MAX_PROBE_ITEM 100
#define MAX_LINE_LENGTH 1024
#define MAX_NAME_LEN  50

/***
 * @param cmd with return value
 * @return
 * 1 is true, 0 error
 */
int exec_cmd_test_with_res(const char *cmd, char *result);

/***
 * @param cmd
 * @return
 * 1 is true, 0 error
 */
int exec_cmd_test(const char *cmd);

void build_ipc_body(struct probe_s *probe, struct ipc_body_s* ipc_body);

int CheckProbeLog(char *logFile, int proc_id, char (*name_record)[MAX_NAME_LEN], char *probe_pref);

int CheckoutHaveSpeProbe(char (*name_record)[MAX_NAME_LEN], char *probe);

#endif