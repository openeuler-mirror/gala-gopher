/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Mr.lu
 * Create: 2021-09-17
 * Description: tcp module
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "bpf.h"
#include "tcp.h"

/*
127.0.0.1:38338users:(("lubanagent",pid=1709,fd=4))
0.0.0.0:30467users:(("kube-proxy",pid=1528,fd=18))
0.0.0.0:31075users:(("kube-proxy",pid=1528,fd=17))
127.0.0.1:38339users:(("lubanagent",pid=1710,fd=4))
127.0.0.1:10248users:(("kubelet",pid=1954,fd=24))
0.0.0.0:32136users:(("kube-proxy",pid=1528,fd=21))
*:10250users:(("kubelet",pid=1954,fd=25))
[::]:111users:(("rpcbind",pid=1493,fd=9))
*:10256users:(("kube-proxy",pid=1528,fd=13))
[::]:22users:(("sshd",pid=1952,fd=4))
*/
#define SS_LISTEN_PORTS_COMMAND "ss -anptl | awk '{if (NR >1) print $4 $6}'"

/*
7.183.6.160:49552|10.32.0.1:443@users:(("kube-rbac-proxy",pid=8302,fd=8))
7.183.6.160:57239|10.243.116.55:179@users:(("bird",pid=8769,fd=21))
7.183.6.160:35605|10.247.120.26:179@users:(("bird",pid=8769,fd=10))
7.183.6.160:22|10.136.115.208:56802@users:(("sshd",pid=1264958,fd=3),("sshd",pid=1264945,fd=3))
[::ffff:7.183.6.160]:10250|[::ffff:10.28.19.57]:35859@users:(("kubelet",pid=1954,fd=32))
[::ffff:7.183.6.160]:10250|[::ffff:10.28.18.95]:51694@users:(("kubelet",pid=1954,fd=33))
*/
#define SS_ESTAB_COMMAND "ss -anpt | grep ESTAB |  awk '{print $4 \"|\" $5 \"@\" $6}'"

#define LS_SOCK_INODE_CMD \
    "/usr/bin/ls -l /proc/%d/fd/%d | /usr/bin/awk -F '[' '{print $2}' | /usr/bin/awk -F ']' '{print $1}'"

#define PORT_LEN 11
#define PID_LEN 32
#define FID_LEN 32


static char __is_digit_str(const char *s)
{
    int len = (int)strlen(s);
    for (int i = 0; i < len; i++) {
        if (!(isdigit(s[i])))
            return 0;
    }
    return 1;
}

static int __get_next_str_offset(const char *s, const char* target)
{
    char *p;

    p = strstr(s, target);
    if ((p != NULL) && (p > s))
        return p - s;

    return -1;
}

static int __get_sub_str(const char *s, const char* start, const char *end,
                                 char* sub_str_buf, unsigned int buf_len)
{
    const char *p2, *p1;
    int len;

    if (s == NULL)
        return -1;

    // Point to end, if no terminator is specified
    if (end == NULL) {
        p2 = s + strlen(s);
    } else {
        p2 = strstr(s, end);
        if (p2 == NULL)
            return -1;
    }

    // Point to start, if no start character is specified
    if (start == NULL) {
        p1 = s;
    } else {
        p1 = strstr(s, start);
        if (p1 == NULL)
            return -1;

        p1 += strlen(start);
    }

    len = (int)(p2 - p1);
    if ((len <= 0) || (len >= buf_len))
        return -1;

    (void)memcpy(sub_str_buf, p1, len);
    sub_str_buf[len] = 0;
    return 0;
}

static int __erase_square_brackets(const char* s, char *buf, unsigned int buf_len)
{
    char *p1, *p2;
    int len;
    char tmp[LINE_BUF_LEN];

    p1 = strchr(s, '[');
    p2 = strchr(s, ']');
    if ((p1 == NULL) || (p2 == NULL))
        return -1;

    if (p2 <= p1)
        return -1;

    if (__get_sub_str(s, "[", "]", tmp, LINE_BUF_LEN) < 0)
        return -1;

    len = (int)strlen(tmp);
    if (len >= buf_len)
        return -1;

    (void)memcpy(buf, tmp, len);
    buf[len] = 0;
    return 0;
}

/*
input : [::ffff:7.183.6.160]:10250
7.183.6.160:57239
*/
static int __get_estab_addr(const char *s, struct ip_addr* ip_addr,
               const char *addr_buf)
{
    char *p;
    int local_len, port_len, ip_len;
    char port_str[PORT_LEN];

    p = strrchr(addr_buf, ':');
    if (p == NULL)
        goto err;

    local_len = (int)strlen(addr_buf);
    ip_len = p - addr_buf;
    if ((ip_len >= local_len) || (ip_len <= 0))
        goto err;

    (void)memcpy(ip_addr->ip, addr_buf, ip_len);
    ip_addr->ip[ip_len] = 0;

    if (__erase_square_brackets((const char*)ip_addr->ip, ip_addr->ip, IP_STR_LEN) == 0) {
        ip_addr->ipv4 = 0;
    } else {
        ip_addr->ipv4 = 1;
    }

    port_len = local_len - ip_len - 1;
    if ((port_len <= 0) || (port_len >= PORT_LEN))
        goto err;

    (void)memcpy(port_str, p + 1, port_len);
    port_str[port_len] = 0;
    if (__is_digit_str((const char *)port_str) == 0)
        goto err;

    ip_addr->port = (unsigned int)atoi(port_str);
    return 0;
err:
    return -1;
}

static struct tcp_estab_comm* __get_estab_comm(const char *start, unsigned int len)
{
    /* ("sshd",pid=1264958,fd=3) */
    char comm[TASK_COMM_LEN];
    char pid_s[PID_LEN];
    char fd_s[FID_LEN];
    char tmp[LINE_BUF_LEN];
    const char *s = tmp;
    struct tcp_estab_comm *te_comm;

    if ((start == NULL) || (len >= LINE_BUF_LEN))
        return NULL;

    (void)memcpy(tmp, start, len);
    tmp[len] = 0;

    if (__get_sub_str(s, "(\"", "\",", comm, TASK_COMM_LEN) ||
        __get_sub_str(s, "pid=", ",fd", pid_s, PID_LEN) ||
        __get_sub_str(s, ",fd=", ")", fd_s, FID_LEN) ||
        !__is_digit_str((const char *)pid_s) ||
        !__is_digit_str((const char *)fd_s)) {
        return NULL;
    }

    te_comm = (struct tcp_estab_comm *)malloc(sizeof(struct tcp_estab_comm));
    if (te_comm == NULL) {
        return NULL;
    }
    te_comm->comm[0] = 0;
    (void)strcpy(te_comm->comm, comm);
    te_comm->pid = (unsigned int)atoi(pid_s);
    te_comm->fd = (unsigned int)atoi(fd_s);
    return te_comm;
}

static int __add_estab_comm(struct tcp_estab* te, const struct tcp_estab_comm *te_comm)
{
    if (te->te_comm_num >= TCP_ESTAB_COMM_MAX)
        return -1;

    te->te_comm[te->te_comm_num++] = (struct tcp_estab_comm *)te_comm;
    return 0;
}

static int __add_estab(struct tcp_estabs* tes, struct tcp_estab* te)
{
    if (tes->te_num >= TCP_ESTAB_MAX)
        return -1;

    tes->te[tes->te_num++] = te;
    return 0;
}

static struct tcp_estab* __new_estab()
{
    struct tcp_estab* te;

    te = (struct tcp_estab *)malloc(sizeof(struct tcp_estab));
    if (te == NULL)
        return NULL;

    (void)memset(te, 0, sizeof(struct tcp_estab));
    return te;
}

static void __free_estab(struct tcp_estab** pte)
{
    struct tcp_estab* te = *pte;
    if (te == NULL)
        return;

    for (int i = 0; i < te->te_comm_num; i++) {
        if (te->te_comm[i]) {
            (void)free(te->te_comm[i]);
            te->te_comm[i] = NULL;
        }
    }
    (void)free(te);
    *pte = NULL;
    return;
}

static struct tcp_estabs* __new_estabs()
{
    struct tcp_estabs* tes;

    tes = (struct tcp_estabs *)malloc(sizeof(struct tcp_estabs));
    if (tes == NULL)
        return NULL;

    (void)memset(tes, 0, sizeof(struct tcp_estabs));
    return tes;
}

static void __free_estabs(struct tcp_estabs** ptes)
{
    struct tcp_estabs* tes = *ptes;
    if (tes == NULL)
        return;

    for (int i = 0; i < tes->te_num; i++) {
        if (tes->te[i])
            __free_estab(&(tes->te[i]));
    }
    (void)free(tes);
    *ptes = NULL;
    return;
}


/*
    input : 7.183.6.160:22|10.136.115.208:56802@users:(("sshd",pid=1264958,fd=3),("sshd",pid=1264945,fd=3))
*/
static int __get_estab(const char *s, struct tcp_estab* te)
{
    int ret;
    int offset;
    char *start, *end;
    char addr_str[IP_STR_LEN];
    char comms_str[LINE_BUF_LEN];
    struct tcp_estab_comm *te_comm;

    // get establish tcp local address and port
    addr_str[0] = 0;
    if (__get_sub_str(s, NULL, "|", addr_str, IP_STR_LEN) ||
        __get_estab_addr(s, &(te->local), addr_str)) {
        goto err;
    }

    // get establish tcp remote address and port
    addr_str[0] = 0;
    if (__get_sub_str(s, "|", "@", addr_str, IP_STR_LEN) ||
        __get_estab_addr(s, &(te->remote), addr_str)) {
        goto err;
    }

    // get all comm, pid, fd of establish tcp
    ret = __get_sub_str(s, "@users:(", NULL, comms_str, LINE_BUF_LEN);
    if (ret < 0)
        goto err;

    comms_str[strlen(comms_str) - 1] = 0; // Delete last character ')'

    // one by one
    start = comms_str;
    end = start + strlen(comms_str);
    do {
        if (start >= end)
            break;

        offset = __get_next_str_offset((const char *)start, ",(");
        if (offset < 0)
            break;

        // get one comm, pid, fd of establish tcp
        te_comm = __get_estab_comm((const char*)start, offset);
        if (te_comm != NULL) {
            if (__add_estab_comm(te, te_comm) < 0)
               (void)free(te_comm);
        }
        start += offset + 1;
    } while (1);

    // get last(or only one) comm, pid, fd of establish tcp
    te_comm = __get_estab_comm((const char*)start, strlen(start));
    if (te_comm != NULL) {
        if (__add_estab_comm(te, te_comm) < 0)
            (void)free(te_comm);
    }

    return 0;
err:
    return -1;
}


static int __get_estabs(struct tcp_estabs* tes)
{
    char line[LINE_BUF_LEN];
    FILE *f;
    const char *command = SS_ESTAB_COMMAND;
    struct tcp_estab* te;
    int ret;

    f = popen(command, "r");
    if (f == NULL)
        return -1;

    while (!feof(f)) {
        (void)memset(line, 0, LINE_BUF_LEN);
        if (fgets(line, LINE_BUF_LEN, f) == NULL)
            break;

        te = __new_estab();
        if (te == NULL)
            break;

        ret = __get_estab((const char *)line, te);
        if (ret < 0) {
            __free_estab(&te);
            continue;
        }

        ret = __add_estab(tes, te);
        if (ret < 0)
            __free_estab(&te);
    }
    (void)pclose(f);
    return 0;
}

/*
                       _______
                       |     |
   s example: 127.0.0.1:38338users:(("lubanagent",pid=1709,fd=4))
*/
static int __get_listen_port(const char *s, unsigned int *port)
{
    int ret;
    char port_str[PORT_LEN];
    unsigned int port_num;

    if (strstr(s, "]:")) {
        ret = __get_sub_str(s, "]:", "users:", port_str, PORT_LEN);
        if (ret < 0)
            return -1;
    } else {
        ret = __get_sub_str(s, ":", "users:", port_str, PORT_LEN);
        if (ret < 0)
            return -1;
    }

    if (__is_digit_str((const char *)port_str) == 0)
        return -1;

    port_num = (unsigned int)atoi(port_str);
    if (port_num >= PORT_MAX_NUM)
        return -1;

    *port = port_num;
    return 0;
}

/*
                                     ____________
                                     |          |
   s example: 127.0.0.1:38338users:(("lubanagent",pid=1709,fd=4))
*/
static int __get_listen_comm(const char *s, char *comm_buf, unsigned int buf_len)
{
    return __get_sub_str(s, "(\"", "\",pid", comm_buf, buf_len);
}

/*
                                                     ______
                                                     |    |
   s example: 127.0.0.1:38338users:(("lubanagent",pid=1709,fd=4))
*/
static int __get_listen_pid(const char *s, unsigned int *pid)
{
    int ret;
    char pid_str[PID_LEN];

    ret = __get_sub_str(s, "pid=", ",fd=", pid_str, PID_LEN);
    if (ret < 0)
        return -1;

    if (__is_digit_str((const char *)pid_str) == 0)
        return -1;

    *pid = (unsigned int)atoi(pid_str);
    return 0;
}

/*
   s example: 127.0.0.1:38338users:(("lubanagent",pid=1709,fd=4))
*/
static int __get_listen_fd(const char *s, int *fd)
{
    int ret;
    char fd_str[FID_LEN];

    ret = __get_sub_str(s, "fd=", NULL, fd_str, FID_LEN);
    if (ret < 0)
        return -1;

    if (__is_digit_str((const char *)fd_str) == 0)
        return -1;

    *fd = atoi(fd_str);
    return 0;
}

static struct tcp_listen_port* __new_tlp(const char *s, unsigned int port)
{
    int ret;
    unsigned pid;
    int fd;
    char comm[TASK_COMM_LEN];
    struct tcp_listen_port* tlp;

    ret = __get_listen_comm(s, comm, TASK_COMM_LEN);
    if (ret < 0)
        return NULL;

    ret = __get_listen_pid(s, &pid);
    if (ret < 0)
        return NULL;

    ret = __get_listen_fd(s, &fd);
    if (ret < 0)
        return NULL;

    tlp = (struct tcp_listen_port *)malloc(sizeof(struct tcp_listen_port));
    if (tlp == NULL)
        return NULL;

    tlp->pid = pid;
    tlp->port = port;
    tlp->fd = fd;
    memcpy(tlp->comm, comm, TASK_COMM_LEN);
    return tlp;
}

static struct tcp_listen_ports* __new_tlps(void)
{
    struct tcp_listen_ports *tlps;
    tlps = (struct tcp_listen_ports *)malloc(sizeof(struct tcp_listen_ports));
    if (tlps == NULL)
        return NULL;

    memset(tlps, 0, sizeof(struct tcp_listen_ports));
    return tlps;
}

static void __free_tlps(struct tcp_listen_ports** ptlps)
{
    struct tcp_listen_ports* tlps = *ptlps;

    for (int i = 0; i < tlps->tlp_num; i++) {
        if (tlps->tlp[i] != NULL) {
            (void)free(tlps->tlp[i]);
            tlps->tlp[i] = NULL;
        }
    }
    tlps->tlp_num = 0;
    (void)free(tlps);
    *ptlps = NULL;
    return;
}

static int __add_tlp(struct tcp_listen_ports* tlps, const struct tcp_listen_port* tlp)
{
    if (tlps->tlp_num >= LTP_MAX_NUM)
        return -1;

    tlps->tlp_hash[tlp->port] += 1;
    tlps->tlp[tlps->tlp_num] = (struct tcp_listen_port *)tlp;
    tlps->tlp_num++;
    return 0;
}

static int __parse_tlp_line(struct tcp_listen_ports* tlps, const char *s)
{
    int ret;
    unsigned int port;

    ret = __get_listen_port(s, &port);
    if (ret < 0) {
        return -1;
    }

    char *user_begin = strstr(s, "((");
    if (user_begin == NULL) {
        return -1;
    }

    struct tcp_listen_port* tlp;
    char *sub_line, *save;
    sub_line = __strtok_r(user_begin, ")", &save);
    while (sub_line != NULL) {
        tlp = __new_tlp(sub_line, port);
        if (tlp != NULL) {
            ret = __add_tlp(tlps, tlp);
            if (ret < 0) {
                (void)free(tlp);
            }
        }
        sub_line = __strtok_r(NULL, ")", &save);
    }

    return ret;
}

static int __get_tlps(struct tcp_listen_ports* tlps)
{
    char line[LINE_BUF_LEN];
    FILE *f;
    const char *command = SS_LISTEN_PORTS_COMMAND;

    f = popen(command, "r");
    if (f == NULL)
        return -1;

    while (feof(f) == 0) {
        (void)memset(line, 0, LINE_BUF_LEN);
        if (fgets(line, LINE_BUF_LEN, f) == NULL)
            break;

        if (__parse_tlp_line(tlps, line) < 0) {
            (void)pclose(f);
            return -1;
        }
    }
    (void)pclose(f);
    return 0;
}

char is_listen_port(unsigned int port, struct tcp_listen_ports* tlps)
{
    if (port >= PORT_MAX_NUM)
        return 0;

    return (tlps->tlp_hash[port] == 0) ? 0 : 1;
}

struct tcp_listen_ports* get_listen_ports(void)
{
    struct tcp_listen_ports* tlps;
    int ret;

    tlps = __new_tlps();
    if (tlps == NULL)
        return NULL;

    ret = __get_tlps(tlps);
    if (ret < 0) {
        __free_tlps(&tlps);
        return NULL;
    }
    return tlps;
}

void free_listen_ports(struct tcp_listen_ports** ptlps)
{
    __free_tlps(ptlps);
}

int get_listen_sock_inode(struct tcp_listen_port *tlp, unsigned long *ino)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, LS_SOCK_INODE_CMD, tlp->pid, tlp->fd);
    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }
    line[0] = 0;
    if (fgets(line, sizeof(line), f) == NULL) {
        (void)pclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    *ino = atoi(line);

    (void)pclose(f);
    return 0;
}

struct tcp_estabs* get_estab_tcps(struct tcp_listen_ports* tlps)
{
    struct tcp_estabs* tes;
    int ret;

    tes = __new_estabs();
    if (tes == NULL)
        return NULL;

    ret = __get_estabs(tes);
    if (ret < 0) {
        __free_estabs(&tes);
        return NULL;
    }

    for (int i = 0; i < tes->te_num; i++) {
        if (is_listen_port(tes->te[i]->local.port, tlps)) {
            tes->te[i]->is_client = 0;
        } else {
            tes->te[i]->is_client = 1;
        }
    }
    return tes;
}

void free_estab_tcps(struct tcp_estabs** ptes)
{
    __free_estabs(ptes);
}


static int __add_tcp_endpoint(struct tcp_endpoints *teps, const struct tcp_endpoint *tep)
{
    if (teps->tep_num >= TCP_ENDPOINT_MAX)
        return -1;

    teps->tep[teps->tep_num++] = (struct tcp_endpoint *)tep;
    return 0;
}

static struct tcp_endpoints* __new_tcp_endpoints()
{
    struct tcp_endpoints* teps = (struct tcp_endpoints *)malloc(sizeof(struct tcp_endpoints));
    if (teps) {
        (void)memset(teps, 0, sizeof(struct tcp_endpoints));
        return teps;
    }
    return teps;
}

static void __free_tcp_endpoints(struct tcp_endpoints** pteps)
{
    int i;
    struct tcp_endpoints* teps = *pteps;

    if (teps == NULL)
        return;

    for (i = 0; i < teps->tep_num; i++) {
        if (teps->tep[i]) {
            (void)free(teps->tep[i]);
            teps->tep[i] = NULL;
        }
    }
    (void)free(teps);
    *pteps = NULL;
    return;
}


static struct tcp_endpoint* __new_tcp_endpoint(enum endpoint_type ep_type, unsigned int port,
                                                     int ipv4, const char *ip, unsigned int pid)
{
    struct tcp_endpoint* tep;

    tep = (struct tcp_endpoint*)malloc(sizeof(struct tcp_endpoint));
    if (tep == NULL)
        return NULL;

    (void)memset(tep, 0, sizeof(struct tcp_endpoint));

    tep->pid = pid;

    if (ep_type == EP_TYPE_LISTEN) {
        tep->ep_type = EP_TYPE_LISTEN;
        tep->port = port;
        goto out;
    }

    if (ep_type == EP_TYPE_IP) {
        tep->ep_type = EP_TYPE_IP;
        if (ipv4 == 1) {
            tep->ep_addr_type = EP_ADDR_IPV4;
            (void)inet_pton(AF_INET, ip, (void *)&tep->addr.in_addr);
        } else {
            tep->ep_addr_type = EP_ADDR_IPV6;
            (void)inet_pton(AF_INET6, ip, (void *)&tep->addr.in6_addr);
        }
        goto out;
    }

    if (ep_type == EP_TYPE_IP_PORT) {
        tep->ep_type = EP_TYPE_IP_PORT;
        if (ipv4 == 1) {
            tep->ep_addr_type = EP_ADDR_IPV4;
            (void)inet_pton(AF_INET, ip, (void *)&tep->addr.in_addr);
        } else {
            tep->ep_addr_type = EP_ADDR_IPV6;
            (void)inet_pton(AF_INET6, ip, (void *)&tep->addr.in6_addr);
        }
        tep->port = port;
        goto out;
    }

out:
    return tep;
}


struct tcp_endpoints *get_tcp_endpoints(struct tcp_listen_ports* tlps, struct tcp_estabs* tes)
{
    int i, j;
    struct tcp_endpoint* tep;
    struct tcp_endpoints* teps;

    teps = __new_tcp_endpoints();
    if (teps == NULL)
        return NULL;

    for (i = 0; i < tlps->tlp_num; i++) {
        tep = __new_tcp_endpoint(EP_TYPE_LISTEN, tlps->tlp[i]->port, 0, NULL, tlps->tlp[i]->pid);
        if (tep) {
            if (__add_tcp_endpoint(teps, tep) < 0)
                (void)free(tep);
        }
    }

    for (i = 0; i < tes->te_num; i++) {
        for (j = 0; j < tes->te[i]->te_comm_num; j++) {
            if (tes->te[i]->is_client) {
                tep = __new_tcp_endpoint(EP_TYPE_IP, 0,
                                         tes->te[i]->local.ipv4,
                                         tes->te[i]->local.ip, tes->te[i]->te_comm[j]->pid);
            } else {
                tep = __new_tcp_endpoint(EP_TYPE_IP_PORT,
                                  tes->te[i]->local.port, tes->te[i]->local.ipv4,
                                  tes->te[i]->local.ip, tes->te[i]->te_comm[j]->pid);
            }
            if (tep) {
                if (__add_tcp_endpoint(teps, tep) < 0)
                    (void)free(tep);
            }
        }
    }
    return teps;
}

void free_tcp_endpoints(struct tcp_endpoints **pteps)
{
    __free_tcp_endpoints(pteps);
}

