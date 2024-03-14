#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>

#define TM_YEAR_BEGIN        1900
#define PATTERN_LOGGER_STR   "[%02d/%02d/%04d %02d:%02d:%02d] - %s"

#define MAX_COUNT             10
#define CONF_PATH            "/etc/web_server.conf"
#define LOG_PATH             "/var/log/web_server.log"
#define PUT_DATA_LEN         128
#define LINE_BUF_LEN         512
#define URL_LEN              512
#define BILLION              1000000000L
#define REQUEST_TMOUT        20L
#define HTTP_OK              200

struct addr {
    char *ip;
    int port;
};

struct addrs_str {
    struct addr addrs[MAX_COUNT];
    int length;
};

#define __FMT_LOGS(buf, size) \
    do { \
        va_list args; \
        buf[0] = 0; \
        va_start(args, format); \
        (void)vsnprintf(buf, (const unsigned int)size, format, args); \
        va_end(args); \
    } while (0)

//创建互斥锁
pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;

int thread_count = 0;
struct addrs_str addrsStr;
int send_all_rate = 0;       //每分钟发送的create/update/delete操作序列数
double send_all_interval = 0.0;
int send_update_rate = 0;   //发送的update占总体操作序列数的比率
int send_update_step = 0;   //发送update的步长，用于控制发送update的比率

void get_log_time(struct tm *t)
{
    time_t now = time((time_t *)(0));
    memset(t, 0, sizeof(struct tm));
    localtime_r(&now, t);
}

static void log_it(const char *format, ...)
{
    FILE *log_fp = fopen(LOG_PATH, "a");
    if (log_fp == NULL) {
        exit(-1);
    }

    char buf[LINE_BUF_LEN];
    struct tm t;

    __FMT_LOGS(buf, LINE_BUF_LEN);
    get_log_time(&t);
    fprintf(log_fp, PATTERN_LOGGER_STR, t.tm_mon + 1, t.tm_mday, t.tm_year + TM_YEAR_BEGIN,
                       t.tm_hour, t.tm_min, t.tm_sec, buf);
    fclose(log_fp);
}

cJSON *get_value_from_file(char *file_path, char *key)
{
    FILE *fp;
    fp = fopen(file_path, "r");
    if (fp == NULL) {
        log_it("[ERROR] get_value_from_file failed\n");
        exit(-1);
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
        log_it("[ERROR] get_value_from_file.cJSON_Parse  %s\n", cJSON_GetErrorPtr());
        exit(-1);
    }

    cJSON *item = cJSON_GetObjectItem(json, key);
    return item;
}

void init(char *file_path)
{
    cJSON *item;
    cJSON *ip;
    cJSON *port;

    //初始化address,ip与port
    addrsStr.length = 0;
    cJSON *address_json = get_value_from_file(file_path, "address");
    if (!cJSON_IsArray(address_json)) {
        exit(-1);
    }

    thread_count = cJSON_GetArraySize(address_json);
    log_it("thread_count %d\n",thread_count);
    if (thread_count <= 0 || thread_count > MAX_COUNT) {
        exit(-1);
    }

    for (int i = 0; i < thread_count; i++) {
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
    send_all_interval = 60.0 / (double)send_all_rate;
    log_it("send_all_rate: %d, send_all_interval: %.2f(s)\n", send_all_rate, send_all_interval);

    // 初始化send_update_rate
    cJSON *send_update_rate_json = get_value_from_file(file_path, "send_update_rate");
    send_update_rate = send_update_rate_json->valueint;
    if (send_update_rate <= 0) {
        send_update_step = 0;
    } else if (send_update_rate > 100) {
        send_update_step = 1;
    } else {
        send_update_step = 100 / send_update_rate;
    }

    log_it("send_update_rate: %d, send_update_step: %d\n", send_update_rate, send_update_step);
}

// http://ip:port/admin-api/system/user/create、http://ip:port/admin-api/system/user/delete、http://ip:port/admin-api/system/role/update
void build_url(char *url, const char *ip, int port, const char *operate)
{
    (void)snprintf(url, LINE_BUF_LEN,
                   "http://%s:%u/admin-api/system/user/%s",
                   ip,
                   port,
                   operate);

}

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
      /* out of memory! */
      log_it("not enough memory (realloc returned NULL)\n");
      return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

#define PUT_DATA_FMT "{\"data\":%d, \"msg\":\"hello backend, %s user!\"}"
int send_request_with_userid(const char *ip, int port, const char *operate, int *userid)
{
    char url[URL_LEN + 1] = {0};
    char put_data[PUT_DATA_LEN] = {0};
    long status;
    struct MemoryStruct chunk;
    cJSON *json = NULL;
    struct curl_slist *headers = NULL;
    int ret = 0;

    CURL *curl = curl_easy_init();        // 创建CURL句柄
    if (curl == NULL) {
        exit(0);
    }

    chunk.memory = malloc(1);  /* grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    build_url(url, ip, port, operate);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TMOUT);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    headers = curl_slist_append(headers, "Content-Type:application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    snprintf(put_data, PUT_DATA_LEN, PUT_DATA_FMT, *userid, operate);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, put_data);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        // 获取response code
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (status != HTTP_OK) {
            log_it("Sent %s but received err response code %d from backend %s:%d\n", operate, status, ip, port);
            ret = -1;
            goto out;
        }
        // get user id that java_app returns
        if (strcmp(operate, "create") == 0) {
            json = cJSON_Parse(chunk.memory);
            if (json == NULL) {
                log_it("Error when parsing response body(%s) from backend %s:%d\n", chunk.memory, ip, port);
                ret = -1;
                goto out;
            }
            cJSON *item = cJSON_GetObjectItem(json, "data");
            *userid = item->valueint;
        }
    } else {
        log_it("Error occurs when sending %s request to backend %s:%d\n", operate, ip, port);
        ret = -1;
    }

out:
    if (json) {
        cJSON_Delete(json);
    }
    free(chunk.memory);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ret;
}


void send_request(char *ip, int port)
{
    int loop;
    struct timespec start_time, now;
    double diff_time;
    int userid;

    while (1) {
        loop = 0;
        clock_gettime(CLOCK_REALTIME, &start_time);

        log_it("==============New loop of requests[%s:%d]===========\n", ip, port);
        // 一分钟内能把请求发完；或者一分钟内请求发不完；这两种情况下都需要进行请求发送
        while (loop < send_all_rate) {
            userid = -1;
            // 轮到发送create方法时，一定发送
            if (send_request_with_userid(ip, port, "create", &userid)) {
                goto next;
            }

            // 轮到发送update方法时，如果距离上次发送已达到step，则发送
            if (send_update_step && (loop % send_update_step == 0)) {
                (void)send_request_with_userid(ip, port, "update", &userid);
            }

            // 轮到发送delete方法时，一定发送
            (void)send_request_with_userid(ip, port, "delete", &userid);

next:
            loop++;
            clock_gettime(CLOCK_REALTIME, &now);
            diff_time = (now.tv_sec - start_time.tv_sec) +
                        (double)( now.tv_nsec - start_time.tv_nsec ) / (double)BILLION;
            if (diff_time >= 60.0) {
                break;
            }

            diff_time = send_all_interval * loop - diff_time;
            if (diff_time > 0.0) {
                usleep(diff_time * 1000000);
            }
        }
    }
}

/*
 * 线程工作函数:周期性发起http request
 */
void *thread_work_func()
{
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

int main()
{
    log_it("Web Server Started\n");

    init(CONF_PATH);

    pthread_t tid[thread_count];

    curl_global_init(CURL_GLOBAL_ALL);

    for (int i = 0; i < thread_count; ++i) {
        pthread_create(&tid[i], NULL, thread_work_func, NULL);
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(tid[i], NULL);
    }

    curl_global_cleanup();
    return 0;
}