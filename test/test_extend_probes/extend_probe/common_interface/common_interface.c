#include "common_interface.h"

static pid_t exec_cmd3(uid_t uid, const char *psz_cmd)
{
    char exec[EXEC_MAX] = {0};
    char **args = NULL;
    int args_num = 0;
    pid_t pid = -1;
    int fd = -1;

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "exec_cmd: fork error");
        goto err;
    } else if (pid == 0) {
        (void)setpgrp();
        (void)prctl(PR_SET_PDEATHSIG, SIGTERM);

        fd = open("/dev/null", O_RDWR, 0);
        if (fd >= 0) {
            (void)dup2(fd, STDIN_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            if (fd != STDERR_FILENO) {
                (void)close(fd);
            }
        }

        if (uid != DEFAULT_USER_ID) {
            if (setuid(uid) != 0) {
                exit(ERROR_SETUID);
            }
        }
        (void)execl("/bin/sh", "sh", "-c", psz_cmd, NULL);
        exit(errno);
    }
err:
    return pid;
}

int exec_cmd_test_with_res(const char *cmd, char *result)
{
    if (exec_cmd(cmd, result, MAX_RETURN_INFO_LEN)) {
        return 0;
    }
    return 1;
}

int exe_cmd2(const char* cmd, char *res, int len)
{
    len--;
    if(cmd == NULL || res == NULL)
        return -1;

    FILE *fp;
    char buf[1024];
    int l, nread = 0;
    fp = popen(cmd, "r");
    if(fp != NULL){
        while(fgets(buf, 1024, fp) != NULL)
        {
            l = strlen(buf);
            if(l >= len - nread)
            {
                memcpy(res + nread, buf, len-nread);
                res[len+1] = '\0';
		pclose(fp);
                return len;
            }
            else
            {
                memcpy(res + nread, buf, l+1);
            }
            nread += l;
        }
        pclose(fp);
        return nread;
    }
    else{
        printf("popen %s failed!\n", cmd);
        return -1;
    }
}

/***
 * @param cmd, only return one line.
 * @return
 * 1 is true, 0 error
 */
int exec_cmd_test(const char *cmd)
{
    char res[MAX_RETURN_INFO_LEN];
    if (!exec_cmd_chroot(cmd, res, MAX_RETURN_INFO_LEN)) {
        return 1;
    }
    return 0;
}

void build_ipc_body(struct probe_s *probe, struct ipc_body_s* ipc_body)
{
    ipc_body->snooper_obj_num = 0;
    ipc_body->probe_flags = 0;

    for (int i = 0; i < SNOOPER_MAX; i++) {
        if (probe->snooper_objs[i] == NULL) {
            continue;
        }

        memcpy(&(ipc_body->snooper_objs[ipc_body->snooper_obj_num]),
               probe->snooper_objs[i], sizeof(struct snooper_obj_s));

        ipc_body->snooper_obj_num++;
    }

    ipc_body->probe_range_flags = probe->probe_range_flags;
    if (probe->is_params_chg) {
        ipc_body->probe_flags |= IPC_FLAGS_PARAMS_CHG;
    }
    if (probe->is_snooper_chg) {
        ipc_body->probe_flags |= IPC_FLAGS_SNOOPER_CHG;
    }
    memcpy(&(ipc_body->probe_param), &probe->probe_param, sizeof(struct probe_params));
    return;
}

int CheckProbeLog(char *logFile, int proc_id, char (*name_record)[MAX_NAME_LEN], char *probe_pref)
{
    const int compare_len = strlen(probe_pref);
    FILE *file = fopen(logFile, "r");
    if (file == NULL) {
        return -1;
    }
    char line[MAX_LINE_LENGTH];
    int processIdFound = 0;
    int tcpCount = 0;
    char proc_id_str[MAX_NAME_LEN];
    proc_id_str[0] = 0;
    sprintf(proc_id_str, "%d", proc_id);
    int name_index = 0;
    while (fgets(line, MAX_LINE_LENGTH, file)) {
        // Check for process_id existence
        if (strstr(line, proc_id_str) == NULL) {
            continue;
        }
        // Extract tcp objects and process_id
        char *token = strtok(line, "|");
        int tokenIndex = 0;
        // Process up to the third column for process_id
        // Ensure it starts with "probe_pref"
        if (strncmp(token, probe_pref, compare_len) == 0) {
            if (name_index < MAX_PROBE_ITEM) {
                strncpy(name_record[name_index], token, strlen(token));
                ++name_index;
            }
        }
    }
    fclose(file);
}

int CheckoutHaveSpeProbe(char (*name_record)[MAX_NAME_LEN], char *probe)
{
    for (int idx = 0; idx < MAX_PROBE_ITEM; ++idx) {
        if (strncmp(probe, name_record[idx], strlen(probe)) == 0) {
            return 1;
        }
    }
    return 0;
}
