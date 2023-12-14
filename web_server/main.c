#include <stdio.h>
#include<pthread.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <time.h>

#define MAX_COUNT 10
#define CONF_PATH           "/etc/web_server.conf"
#define LINE_BUF_LEN        512
#define URL_LEN             512

struct addr {
    char *ip;
    int port;
};

struct addrs_str {
    struct addr addrs[MAX_COUNT];
    int length;
};

//创建互斥锁
pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;

int thread_count = 0;
struct addrs_str addrsStr;
int send_all_rate = 0, send_update_rate = 0;

cJSON *get_value_from_file(char *file_path, char *key) {

    FILE *fp;
    fp = fopen(file_path, "r");
    if (fp == NULL) {
        printf("[ERROR]: get_value_from_file failed");
    }

    char buf[100];
    realpath(file_path, buf);

    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);

    char *content = (char *) malloc(len + 1);

    rewind(fp);
    fread(content, 1, len, fp);
    fclose(fp);

    content[len] = '\0';

    cJSON *json;
    json = cJSON_Parse(content);
    if (!json) {
        printf("Error: get_value_from_file.cJSON_Parse  %s\n", cJSON_GetErrorPtr());
    }

    cJSON *item = cJSON_GetObjectItem(json, key);
    return item;
}

void init(char *file_path) {
    // 初始化线程个数
    cJSON *thread_count_json = get_value_from_file(file_path, "thread_count");
    thread_count = thread_count_json->valueint;

    //初始化address,ip与port
    addrsStr.length = 0;
    cJSON *address_json = get_value_from_file(file_path, "address");
    if (!cJSON_IsArray(address_json)) {
        exit(-1);
    }

    int array_size = cJSON_GetArraySize(address_json);
    cJSON *item;
    cJSON *ip;
    cJSON *port;
    for (int i = 0; i < array_size; i++) {
        item = cJSON_GetArrayItem(address_json, i);
        ip = cJSON_GetObjectItem(item, "ip");
        port = cJSON_GetObjectItem(item, "port");
        addrsStr.addrs[i].ip = ip->valuestring;
        addrsStr.addrs[i].port = port->valueint;
        addrsStr.length++;
    }

    // 初始化send_all_rate
    cJSON *send_all_rate_json = get_value_from_file(file_path, "send_all_rate");
    send_all_rate = send_all_rate_json->valueint;

    // 初始化send_update_rate
    cJSON *send_update_rate_json = get_value_from_file(file_path, "send_update_rate");
    send_update_rate = send_update_rate_json->valueint;
}

// http://ip:port/admin-api/system/user/create、http://ip:port/admin-api/system/user/delete、http://ip:port/admin-api/system/role/update
int build_url(char *url, char *ip, int port, char *operate) {
    if(operate == "update") {
        (void) snprintf(url, LINE_BUF_LEN,
                        "http://%s:%u/admin-api/system/role/%s",
                        ip,
                        port,
                        operate);
    } else {
        (void) snprintf(url, LINE_BUF_LEN,
                        "http://%s:%u/admin-api/system/user/%s",
                        ip,
                        port,
                        operate);
    }

    return 0;
}

void send_request_to_url(char *ip, int port, char *operate) {
    char *url = malloc(URL_LEN + 1);
    (void) memset(url, 0, URL_LEN);

    build_url(url, ip, port, operate);

    CURL *curl = curl_easy_init();        // 创建CURL句柄
    if (curl == NULL) {
        exit(0);
    }

    //设置请求的url
    curl_easy_setopt(curl, CURLOPT_URL, url);

    //设置为put方法
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);

    curl_easy_perform(curl); // 发送数据
    curl_easy_cleanup(curl);
}

void send_request(char *ip, int port) {

    char *operates[] = {
            "create",
            "delete",
            "update"
    };

    while (1) {
        int count = 0;
        int update_count = 0;
        time_t start_time = time(NULL);
        int operate_index = 0;
        
        // 一分钟内能把请求发完；或者一分钟内请求发不完；这两种情况下都需要进行请求发送
        while ((difftime(time(NULL), start_time) < 60 && count < send_all_rate) || count < send_all_rate) {


            // 轮到发送create方法时，一定发送
            if ((operate_index + 1) % 3 == 1) {
                send_request_to_url(ip, port, operates[operate_index]);
                count++;
            } else if ((operate_index + 1) % 3 == 2 && update_count < send_update_rate) {

                // 轮到发送update方法时，选择发送
                send_request_to_url(ip, port, operates[operate_index]);
                update_count++;
                count++;
            } else if ((operate_index + 1) % 3 == 0) {

                // 轮到发送delete方法时，一定发送
                send_request_to_url(ip, port, operates[operate_index]);
                count++;
            }

            operate_index++;

            if (operate_index > 2) {
                operate_index = 0;
            }
        }
    }
}

/*
 * 线程工作函数:周期性发起http request
 */
void *thread_work_func() {
    int islock = 0;
    islock = pthread_mutex_lock(&myMutex);

    if (islock == 0 && addrsStr.length > 0) {
        // 取出地址
        char *ip = addrsStr.addrs[addrsStr.length - 1].ip;
        int port = addrsStr.addrs[addrsStr.length - 1].port;

        addrsStr.length--;

        pthread_mutex_unlock(&myMutex);

        send_request(ip, port);
    }
    return NULL;
}

int main() {
    init(CONF_PATH);

    pthread_t tid[thread_count];

    curl_global_init(CURL_GLOBAL_ALL);

    for (int i = 0; i < thread_count; ++i) {
        pthread_create(&tid[i], NULL, thread_work_func, NULL);
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(tid[i], NULL);
    }

    return 0;
}