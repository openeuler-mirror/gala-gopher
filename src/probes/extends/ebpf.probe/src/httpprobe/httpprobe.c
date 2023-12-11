/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Ernest
 * Create: 2022-08-27
 * Description: http probe user prog
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "bpf.h"
#include "args.h"
#include "kprobe.skel.h"
#include "sslprobe.skel.h"

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "httpprobe.h"

#define HTTP_SLI_METRIC         "http_sli"
#define HTTP_MAX_SLI_METRIC     "http_max_sli"
#define NGINX_PATH              "which nginx"
#define APACHE_PATH             "which httpd"
#define NGINX_SSL_PATH          "ldd $(which nginx) | grep libssl | awk '{print $3}'"
#define APACHE_SSL_PATH         "ldd /etc/httpd/modules/mod_ssl.so | grep libssl | awk '{print $3}'"
#define HTTPD_SSL_PATH          "/etc/httpd/modules/mod_ssl.so"

#define LOAD_HTTP_PROBE(probe_name, end, load) \
    INIT_OPEN_OPTS(probe_name); \
    PREPARE_CUSTOM_BTF(probe_name); \
    OPEN_OPTS(probe_name, end, 1); \
    MAP_SET_PIN_PATH(probe_name, conn_map, HTTP_CONN_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, conn_samp_map, HTTP_CONN_SAMP_PATH, load); \
    LOAD_ATTACH(httpprobe, probe_name, end, load)

#define RM_HTTP_PATH        "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__http*"

#define ATTACH_LIBSSL_FOR(libsslpath, err, success) URETBPF_ATTACH(sslprobe, SSL_read, libsslpath, SSL_read, success); \
    if ((success) <= 0) { \
        fprintf(stderr, "ERROR: attach to tracepoint SSL_read failed\n"); \
        goto err; \
    } \
    URETBPF_ATTACH(sslprobe, SSL_write, libsslpath, SSL_write, success); \
    if ((success) <= 0) { \
        goto err; \
        fprintf(stderr, "ERROR: attach to tracepoint SSL_write failed\n"); \
    }

static char *methods[HTTP_NUMS] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
static struct probe_params_deprecated params = { .period = DEFAULT_PERIOD };

static void get_libssl_path(char *nginx_sslpath, char *apache_sslpath)
{
    FILE *f1 = NULL, *f2 = NULL;
    char buf[PATH_LEN] = {0};

    f1 = popen_chroot(NGINX_PATH, "r");
    if (fgets(buf, PATH_LEN, f1) != NULL && strlen(buf) > 0 && !(buf[strlen(buf) - 1] = 0) && access(buf, F_OK) == 0) {
        if ((f2 = popen_chroot(NGINX_SSL_PATH, "r")) != NULL && fgets(nginx_sslpath, PATH_LEN, f2) != NULL) {
            if (strlen(nginx_sslpath) != 0) {
                nginx_sslpath[strlen(nginx_sslpath) - 1] = 0;
            }
        }
        pclose(f2);
    }
    pclose(f1);
    f1 = popen_chroot(APACHE_PATH, "r");
    if (fgets(buf, PATH_LEN, f1) != NULL && strlen(buf) > 0 && !(buf[strlen(buf) - 1] = 0) &&
        access(buf, F_OK) == 0 && access(HTTPD_SSL_PATH, F_OK) == 0) {
        if ((f2 = popen_chroot(APACHE_SSL_PATH, "r")) != NULL && fgets(apache_sslpath, PATH_LEN, f2) != NULL) {
            if (strlen(apache_sslpath) != 0) {
                apache_sslpath[strlen(apache_sslpath) - 1] = 0;
            }
        }
        pclose(f2);
    }
    pclose(f1);
    if (strcmp(nginx_sslpath, apache_sslpath) == 0) {
        apache_sslpath[0] = '\0';
    }
}

static void print_http_sli(void *ctx, int cpu, void *data, __u32 size)
{
    struct http_request *req = (struct http_request *)data;
    unsigned char ser_ip_str[INET6_ADDRSTRLEN];
    unsigned char cli_ip_str[INET6_ADDRSTRLEN];

    ip_str(req->conn_info.server_ip_info.family, (unsigned char *)&(req->conn_info.server_ip_info.ipaddr),
        ser_ip_str, INET6_ADDRSTRLEN);
    ip_str(req->conn_info.client_ip_info.family, (unsigned char *)&(req->conn_info.client_ip_info.ipaddr),
        cli_ip_str, INET6_ADDRSTRLEN);
    if (req->method == HTTP_UNKNOWN) {
        return;
    }
    (void)fprintf(stdout, "|%s|%u|%d|%s|%s|%s|%hu|%s|%hu|%llu|\n",
        HTTP_SLI_METRIC,
        req->tgid,
        req->skfd,
        "HTTP",
        methods[req->method - 1],
        ser_ip_str,
        req->conn_info.server_ip_info.port,
        cli_ip_str,
        ntohs(req->conn_info.client_ip_info.port),
        req->latestrtt);
    (void)fprintf(stdout, "|%s|%u|%d|%s|%s|%s|%hu|%s|%hu|%llu|\n",
        HTTP_MAX_SLI_METRIC,
        req->tgid,
        req->skfd,
        "HTTP",
        methods[req->method - 1],
        ser_ip_str,
        req->conn_info.server_ip_info.port,
        cli_ip_str,
        ntohs(req->conn_info.client_ip_info.port),
        req->longestrtt);
    (void)fflush(stdout);
}

static void load_args(int args_fd, const struct probe_params_deprecated* params)
{
    __u32 key = 0;
    struct http_args_s args = {0};
    args.period = NS(params->period);
    (void)bpf_map_update_elem(args_fd, &key, &args, BPF_ANY);
}

int main(int argc, char **argv)
{
    int err = 0, success = 0;
    char nginx_libsslpath[PATH_LEN] = {0}, apache_libsslpath[PATH_LEN] = {0};
    struct perf_buffer* pb = NULL;
    FILE *fp = NULL;

    err = args_parse(argc, argv, &params);
    if (err != 0) {
        goto err1;
    }
    INFO("arg parse interval time:%us\n", params.period);

    fp = popen(RM_HTTP_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    get_libssl_path(nginx_libsslpath, apache_libsslpath);
    INIT_BPF_APP(httpprobe, EBPF_RLIM_LIMITED);
    LOAD_HTTP_PROBE(kprobe, err1, 1);
    LOAD_HTTP_PROBE(sslprobe, err2, 1);
    load_args(GET_MAP_FD(kprobe, args_map), &params);
    if (strlen(nginx_libsslpath) != 0) {
        ATTACH_LIBSSL_FOR(nginx_libsslpath, err3, success);
    }
    if (strlen(apache_libsslpath) != 0) {
        ATTACH_LIBSSL_FOR(apache_libsslpath, err3, success);
    }
    pb = create_pref_buffer(GET_MAP_FD(kprobe, http_events), print_http_sli);
    if (pb == NULL) {
        fprintf(stderr, "ERROR: create perf buffer failed\n");
        goto err2;
    }
    poll_pb(pb, params.period * THOUSAND);
    perf_buffer__free(pb);
err3:
    UNLOAD(sslprobe);
    CLEANUP_CUSTOM_BTF(sslprobe);
err2:
    UNLOAD(kprobe);
    CLEANUP_CUSTOM_BTF(kprobe);
err1:
    return -1;
}