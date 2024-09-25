#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "strbuf.h"
#include "event2json.h"

#define MAX_FIELD_NAME 16

#define VAL_WITH_QUOTE 1
#define VAL_WITHOUT_QUOTE 0

// data format as machine_uuid(40)-entityName-entityid(128)
#define ENTITY_ID_LEN 256
// event_id data format as timestamp-entity_id
#define TIMESTAMP_LEN_MAX  128
#define EVENT_ID_LEN  (ENTITY_ID_LEN + TIMESTAMP_LEN_MAX)
#define METRIC_ID_LEN 64

#define COMM_FIELD_TIMESTAMP "Timestamp"
#define COMM_FIELD_SEVER_TXT "SeverityText"
#define COMM_FIELD_SEVER_NO  "SeverityNumber"
#define COMM_FIELD_RESOURCE  "Resource"
#define COMM_FIELD_ATTRS     "Attributes"
#define COMM_FIELD_BODY      "Body"

enum {
    LOG_FIELD_TIMESTAMP = 0,
    LOG_FIELD_SEVERITYTEXT,
    LOG_FIELD_SEVERITYNUMBER,
    LOG_FIELD_RESOURCE,
    LOG_FIELD_ATTRIBUTES,
    LOG_FIELD_BODY,
    LOG_FIELD_MAX
};

static char gLogField[LOG_FIELD_MAX][MAX_FIELD_NAME] = {
    {COMM_FIELD_TIMESTAMP},
    {COMM_FIELD_SEVER_TXT},
    {COMM_FIELD_SEVER_NO},
    {COMM_FIELD_RESOURCE},
    {COMM_FIELD_ATTRS},
    {COMM_FIELD_BODY}
};

enum {
    EVT_ORIG_FIELD_ENTITY_NAME = 0,
    EVT_ORIG_FIELD_ENTITY_ID,
    EVT_ORIG_FIELD_METRIC,
    EVT_ORIG_FIELD_PID,
    EVT_ORIG_FIELD_COMM,
    EVT_ORIG_FIELD_IP,
    EVT_ORIG_FIELD_CONTAINER_ID,
    EVT_ORIG_FIELD_POD,
    EVT_ORIG_FIELD_DEVICE,
    EVT_ORIG_FIELD_SEVER_TXT,
    EVT_ORIG_FIELD_SEVER_NO,
    EVT_ORIG_FIELD_BODY,
    EVT_ORIG_FIELD_MAX
};

enum {
    EVT_FIELD_TIMESTAMP = 0,
    EVT_FIELD_EVENT_ID,
    EVT_FIELD_ATTRIBUTES,
    EVT_FIELD_RESOURCE,
    EVT_FIELD_SEVER_TXT,
    EVT_FIELD_SEVER_NO,
    EVT_FIELD_BODY,
    EVT_FIELD_MAX
};

static char gEvtField[EVT_FIELD_MAX][MAX_FIELD_NAME] = {
    {COMM_FIELD_TIMESTAMP},
    {"event_id"},
    {COMM_FIELD_ATTRS},
    {COMM_FIELD_RESOURCE},
    {COMM_FIELD_SEVER_TXT},
    {COMM_FIELD_SEVER_NO},
    {COMM_FIELD_BODY}
};

// opentelemetry log

static inline void error_log2json_buffer_no_enough_space(void)
{
    ERROR("[INGRESS] the log2json buffer has not enough space.\n");
}

// fill format: "<field_name>":<field_val>
// if `fillQuote` is true, fill format: "<field_name>":"<field_val>"
static int fill_log_field_simple(strbuf_t *dest, strbuf_t *fieldVal, const char *fieldName, int fillQuote)
{
    size_t fieldNameSize = strlen(fieldName);
    size_t requiredSize = fieldNameSize + fieldVal->len + 3;

    if (fillQuote) { requiredSize += 2; }

    if (requiredSize >= dest->size) {
        error_log2json_buffer_no_enough_space();
        return -1;
    }

    strbuf_append_chr(dest, '\"');
    strbuf_append_str(dest, fieldName, fieldNameSize);
    strbuf_append_chr(dest, '\"');

    strbuf_append_chr(dest, ':');

    if (fillQuote) { strbuf_append_chr(dest, '\"'); }
    strbuf_append_str(dest, fieldVal->buf, fieldVal->len);
    if (fillQuote) { strbuf_append_chr(dest, '\"'); }

    return 0;
}

// fill format: ,"host.id":"<host.id>","host.name":"<host.name>"
static int enrich_resource_with_host_info(IngressMgr *mgr, strbuf_t *dest)
{
    int copySize;
    IMDB_NodeInfo nodeInfo = mgr->imdbMgr->nodeInfo;

    copySize = snprintf(dest->buf, dest->size, ",\"host.id\":\"%s\",\"host.name\":\"%s\",\"host.ip\":\"%s\"",
                        nodeInfo.systemUuid, nodeInfo.hostName, nodeInfo.hostIP);
    if (copySize < 0 || copySize >= dest->size) {
        error_log2json_buffer_no_enough_space();
        return -1;
    }
    strbuf_update_offset(dest, copySize);

    return 0;
}

static int fill_log_field_resource(IngressMgr *mgr, strbuf_t *dest, strbuf_t *field)
{
    int ret;

    // simply validate resource json format
    if (field->len < 2 || field->buf[0] != '{' || field->buf[field->len - 1] != '}') {
        ERROR("[INGRESS] the resource json format of log validate failed.\n");
        return -1;
    }

    ret = fill_log_field_simple(dest, field, gLogField[LOG_FIELD_RESOURCE], VAL_WITHOUT_QUOTE);
    if (ret) {
        return -1;
    }

    // rollback '}' character
    strbuf_update_offset(dest, -1);

    ret = enrich_resource_with_host_info(mgr, dest);
    if (ret) {
        return -1;
    }

    // restore '}' character
    if (strbuf_append_chr_with_check(dest, '}')) {
        error_log2json_buffer_no_enough_space();
        return -1;
    }

    return 0;
}

static int fill_log_field(IngressMgr *mgr, strbuf_t *dest, strbuf_t *field, int fieldNumber)
{
    switch (fieldNumber) {
        case LOG_FIELD_TIMESTAMP:
        case LOG_FIELD_SEVERITYTEXT:
        case LOG_FIELD_SEVERITYNUMBER:
        case LOG_FIELD_ATTRIBUTES:
        case LOG_FIELD_BODY:
            return fill_log_field_simple(dest, field, gLogField[fieldNumber], VAL_WITHOUT_QUOTE);
        case LOG_FIELD_RESOURCE:
            return fill_log_field_resource(mgr, dest, field);
        default:
            return -1;
    }

    return 0;
}

/*
 * source format like: |<Timestamp>|<SeverityText>|<SeverityNumber>|<Resource>|<Attributes>|<Body>|
 * target format like:
 * {
 *     "Timestamp": <Timestamp>,
 *     "SeverityText": <SeverityText>,
 *     "SeverityNumber": <SeverityNumber>,
 *     "Body": <Body>,
 *     "Resource": {
 *         "host.id": <host.id>,
 *         "host.name": <host.name>,
 *         "thread.pid": <thread.pid>,
 *         "thread.tgid": <thread.tgid>
 *     },
 *     "Attributes": {
 *         "event.name": <event.name>,
 *         "event.category": <event.category>,
 *         "event.loc": <event.loc>
 *     }
 * }
 */
int LogData2Json(IngressMgr *mgr, const char *logData, char *jsonFmt, int jsonSize)
{
    const char bar = '|';
    char *barNow = (char *)logData;
    char *barNext = NULL;
    strbuf_t jsonFmtRemain = {
        .buf = jsonFmt,
        .size = jsonSize
    };
    strbuf_t field;
    int ret;

    if (*barNow != bar) {
        ERROR("[INGRESS] log data format error: first charactor is not |\n");
        return -1;
    }

    if (strbuf_append_chr_with_check(&jsonFmtRemain, '{')) {
        error_log2json_buffer_no_enough_space();
        return -1;
    }

    for (int fieldNo = 0; fieldNo < LOG_FIELD_MAX; fieldNo++) {
        barNext = strchr(barNow + 1, bar);
        if (barNext == NULL) {
            return -1;
        }

        field.buf = barNow + 1;
        field.len = barNext - barNow - 1;
        ret = fill_log_field(mgr, &jsonFmtRemain, &field, fieldNo);
        if (ret) {
            return -1;
        }

        barNow = barNext;

        if (fieldNo != LOG_FIELD_MAX - 1) {
            if (strbuf_append_chr_with_check(&jsonFmtRemain, ',')) {
                error_log2json_buffer_no_enough_space();
                return -1;
            }
        }
    }

    if (strbuf_append_str_with_check(&jsonFmtRemain, "}\0", 2)) {
        error_log2json_buffer_no_enough_space();
        return -1;
    }

    return 0;
}

// gopher event

static inline void error_evt2json_buffer_no_enough_space(void)
{
    ERROR("[INGRESS] the event2json buffer has not enough space.\n");
}

static int get_event_fields(strbuf_t *evtFields, int num, const char *evtData)
{
    const char bar = '|';
    char *barNow = (char *)evtData;
    char *barNext = NULL;
    int fieldNo;

    if (*barNow != bar) {
        ERROR("[INGRESS] event data format error: first charactor is not |\n");
        return -1;
    }

    for (fieldNo = 0; fieldNo < num; fieldNo++) {
        barNext = strchr(barNow + 1, bar);
        if (barNext == NULL) {
            ERROR("[INGRESS] event data format error: some field miss.\n");
            return -1;
        }

        evtFields[fieldNo].buf = barNow + 1;
        evtFields[fieldNo].len = barNext - barNow - 1;

        barNow = barNext;
    }

    // validate required fields
    if (evtFields[EVT_ORIG_FIELD_ENTITY_NAME].len == 0 || evtFields[EVT_ORIG_FIELD_ENTITY_ID].len == 0 ||
        evtFields[EVT_ORIG_FIELD_METRIC].len == 0) {
        ERROR("[INGRESS] event data format error: failed to validate required fields.\n");
        return -1;
    }

    return 0;
}

// 对entityID中出现的特殊字符进行替换，替换为':'
static void transfer_entityId(char *entityId)
{
    int i, j;
    char specialSymbols[] = {'/'};     // 不支持的符号集合，可以新增
    size_t symSize = sizeof(specialSymbols) / sizeof(specialSymbols[0]);

    for (i = 0; entityId[i] != '\0'; i++) {
        for (j = 0; j < symSize; j++) {
            if (entityId[i] == specialSymbols[j]) {
                entityId[i] = ':';
            }
        }
    }
    return;
}

static void get_curr_timestamp_ms(time_t *timestamp)
{
    time_t now;

    time(&now);
    *timestamp = now * THOUSAND;
}

// format: <machine_id>_<entity_name>_<orig_entity_id>
static int get_entityId(char *entityId, int size, IMDB_NodeInfo *nodeInfo, strbuf_t *entityName, strbuf_t *origEntityId)
{
    int requiredSize;
#define __MAX_MACHINE_ID_LEN (MAX_IMDB_SYSTEM_UUID_LEN + MAX_IMDB_HOSTIP_LEN)
    char machineId[__MAX_MACHINE_ID_LEN];
    size_t machineIdLen;
    char *entityIdPos = NULL;
    strbuf_t sbuf = {
        .buf = entityId,
        .size = size
    };

    machineId[0] = 0;
    (void)snprintf(machineId, sizeof(machineId), "%s-%s", nodeInfo->systemUuid, nodeInfo->hostIP);

    machineIdLen = strlen(machineId);
    requiredSize = machineIdLen + entityName->len + origEntityId->len + 3;
    if (sbuf.size < requiredSize) {
        ERROR("[INGRESS] get event entityId failed: space not enough.\n");
        return -1;
    }

    strbuf_append_str(&sbuf, machineId, machineIdLen);
    strbuf_append_chr(&sbuf, '_');
    strbuf_append_str(&sbuf, entityName->buf, entityName->len);
    strbuf_append_chr(&sbuf, '_');
    entityIdPos = sbuf.buf; // record the location of the orig entityId for translation
    strbuf_append_str(&sbuf, origEntityId->buf, origEntityId->len);
    strbuf_append_chr(&sbuf, '\0');

    transfer_entityId(entityIdPos);

    return 0;
}

// format: <timestamp>_<entity_id>
static int get_eventId(char *eventId, int size, time_t timestamp, const char *entityId)
{
    strbuf_t sbuf = {
        .buf = eventId,
        .size = size
    };
    int ret;

    ret = snprintf(sbuf.buf, sbuf.size, "%lld_%s", timestamp, entityId);
    if (ret < 0 || ret >= sbuf.size) {
        ERROR("[INGRESS] get event eventId failed: space not enough.\n");
        return -1;
    }
    strbuf_update_offset(&sbuf, ret);
    strbuf_append_chr(&sbuf, '\0');

    return 0;
}

// format: "gala_gopher_<entity_name>_<metric_name>"
static int get_metricId(char *metricId, int size, strbuf_t *entityName, strbuf_t *metricName)
{
    int requiredSize;
    const char *prefix = "gala_gopher";
    size_t prefixLen = strlen(prefix);
    strbuf_t sbuf = {
        .buf = metricId,
        .size = size
    };

    requiredSize = prefixLen + entityName->len + metricName->len + 3;
    if (sbuf.size < requiredSize) {
        ERROR("[INGRESS] get event metricId failed: space not enough.\n");
        return -1;
    }

    strbuf_append_str(&sbuf, prefix, prefixLen);
    strbuf_append_chr(&sbuf, '_');
    strbuf_append_str(&sbuf, entityName->buf, entityName->len);
    strbuf_append_chr(&sbuf, '_');
    strbuf_append_str(&sbuf, metricName->buf, metricName->len);
    strbuf_append_chr(&sbuf, '\0');

    return 0;
}

static int fill_evt_field_timestamp(strbuf_t *dest, time_t timestamp)
{
    char tsStr[16];
    strbuf_t field;

    (void)snprintf(tsStr, sizeof(tsStr), "%lld", (long long)timestamp);

    field.buf = (char *)tsStr;
    field.len = strlen(tsStr);
    return fill_log_field_simple(dest, &field, gEvtField[EVT_FIELD_TIMESTAMP], VAL_WITHOUT_QUOTE);
}

static int fill_evt_field_eventId(strbuf_t *dest, const char *eventId)
{
    strbuf_t field;

    field.buf = (char *)eventId;
    field.len = strlen(eventId);
    return fill_log_field_simple(dest, &field, gEvtField[EVT_FIELD_EVENT_ID], VAL_WITH_QUOTE);
}

static int fill_evt_field_attrs(strbuf_t *dest, const char *entityId, const char *eventId)
{
    char *fmt;
    int ret;

    fmt = "\"%s\":{\"entity_id\":\"%s\",\"event_id\":\"%s\",\"event_type\":\"sys\"}";
    ret = snprintf(dest->buf, dest->size, fmt, gEvtField[EVT_FIELD_ATTRIBUTES], entityId, eventId);
    if (ret < 0 || ret >= dest->size) {
        error_evt2json_buffer_no_enough_space();
        return -1;
    }
    strbuf_update_offset(dest, ret);

    return 0;
}

#define __EVT_LABEL_HOST "Host"
#define __EVT_LABEL_PID "PID"
#define __EVT_LABEL_COMM "COMM"
#define __EVT_LABEL_IP "IP"
#define __EVT_LABEL_CONTAINER_ID "ContainerID"
#define __EVT_LABEL_POD "POD"
#define __EVT_LABEL_DEVICE "Device"

// output like: `"labels": {"Host": "", "PID":""}`
static int fill_evt_field_labels(strbuf_t *dest, strbuf_t evtFields[EVT_ORIG_FIELD_MAX], IngressMgr *mgr)
{
    int ret;
    char *str;
    strbuf_t valBuf;
    char hostVal[LINE_BUF_LEN];
    int labelIdx[] = {EVT_ORIG_FIELD_PID, EVT_ORIG_FIELD_COMM, EVT_ORIG_FIELD_IP,
                      EVT_ORIG_FIELD_CONTAINER_ID, EVT_ORIG_FIELD_POD, EVT_ORIG_FIELD_DEVICE};
    char *labelName[] = {__EVT_LABEL_PID, __EVT_LABEL_COMM, __EVT_LABEL_IP,
                         __EVT_LABEL_CONTAINER_ID, __EVT_LABEL_POD, __EVT_LABEL_DEVICE};
    int i;

    hostVal[0] = 0;
    (void)snprintf(hostVal, LINE_BUF_LEN, "%s-%s", mgr->imdbMgr->nodeInfo.systemUuid, mgr->imdbMgr->nodeInfo.hostIP);

    str = "\"labels\":{";
    ret = strbuf_append_str_with_check(dest, str, strlen(str));
    if (ret) {
        goto err;
    }

    valBuf.buf = hostVal;
    valBuf.len = strlen(hostVal);
    ret = fill_log_field_simple(dest, &valBuf, __EVT_LABEL_HOST, VAL_WITH_QUOTE);
    if (ret) {
        goto err;
    }

    for (i = 0; i < sizeof(labelIdx) / sizeof(labelIdx[0]); i++) {
        ret = strbuf_append_chr_with_check(dest, ',');
        if (ret) {
            goto err;
        }
        ret = fill_log_field_simple(dest, &evtFields[labelIdx[i]], labelName[i], VAL_WITH_QUOTE);
        if (ret) {
            goto err;
        }
    }

    ret = strbuf_append_chr_with_check(dest, '}');
    if (ret) {
        goto err;
    }

    return 0;
err:
    error_evt2json_buffer_no_enough_space();
    return -1;
}

// output like `"Resource": {"metric":"","labels":{}}`
static int fill_evt_field_resource(strbuf_t *dest, const char *metricId, strbuf_t evtFields[EVT_ORIG_FIELD_MAX],
                                   IngressMgr *mgr)
{
    char *fmt;
    int ret;

    fmt = "\"%s\":{\"metric\":\"%s\",";
    ret = snprintf(dest->buf, dest->size, fmt, gEvtField[EVT_FIELD_RESOURCE], metricId);
    if (ret < 0 || ret >= dest->size) {
        error_evt2json_buffer_no_enough_space();
        return -1;
    }
    strbuf_update_offset(dest, ret);

    ret = fill_evt_field_labels(dest, evtFields, mgr);
    if (ret) {
        return -1;
    }

    ret = strbuf_append_chr_with_check(dest, '}');
    if (ret) {
        error_evt2json_buffer_no_enough_space();
        return -1;
    }

    return 0;
}

/*
 * source format like: "|EntityName|EntityID|metric|ServerityText|ServerityNumber|Body|"
 * output format like:
 * {
 *   "Timestamp": 15869605860,
 *   "event_id": "1586xxx_xxxx",
 *   "Attributes": {
 *     "entity_id": "xx",
 *     "event_id": "1586xxx_xxxx",
 *     "event_type": "sys"
 *   },
 *   "Resource": {
 *     "metric": "gala_gopher_tcp_link_health_rx_bytes",
 *     "labels": {
 *       "Host": "2c1c455d-24a5-897c-ea11-bc08f2d510da-192.168.128.123",
 *       "PID": "1123",
 *       "COMM": "ceph2-10.xxx.xxx.xxx",
 *       "IP": "sip 187.10.1.123, dip 192.136.123.1",
 *       "ContainerID": "2c1c455d-24a5-897c-ea11-bc08f2d510da",
 *       "POD": "",
 *       "Device": ""
 *     }
 *   },
 *   "SeverityText": "WARN",
 *   "SeverityNumber": 13,
 *   "Body": "20200415T072306-0700 WARN Entity(xx)  occurred gala_gopher_tcp_link_health_rx_bytes event."
 * }
 */
int EventData2Json(IngressMgr *mgr, const char *evtData, char *jsonFmt, int jsonSize)
{
    strbuf_t evtFields[EVT_ORIG_FIELD_MAX] = {0};
    time_t timestamp;
    char entityId[ENTITY_ID_LEN];
    char eventId[EVENT_ID_LEN];
    char metricId[METRIC_ID_LEN];
    int fieldNo;
    int ret;
    strbuf_t jsonFmtRemain = {
        .buf = jsonFmt,
        .size = jsonSize
    };

    ret = get_event_fields(evtFields, EVT_ORIG_FIELD_MAX, evtData);
    if (ret) {
        return -1;
    }

    get_curr_timestamp_ms(&timestamp);
    if (get_entityId(entityId, sizeof(entityId), &mgr->imdbMgr->nodeInfo,
                     &evtFields[EVT_ORIG_FIELD_ENTITY_NAME], &evtFields[EVT_ORIG_FIELD_ENTITY_ID])) {
        return -1;
    }
    if (get_eventId(eventId, sizeof(eventId), timestamp, entityId)) {
        return -1;
    }
    if (get_metricId(metricId, sizeof(metricId), &evtFields[EVT_ORIG_FIELD_ENTITY_NAME],
                     &evtFields[EVT_ORIG_FIELD_METRIC])) {
        return -1;
    }

    if (strbuf_append_chr_with_check(&jsonFmtRemain, '{')) {
        error_evt2json_buffer_no_enough_space();
        return -1;
    }

    for (fieldNo = 0; fieldNo < EVT_FIELD_MAX; fieldNo++) {
        switch (fieldNo) {
            case EVT_FIELD_TIMESTAMP:
                ret = fill_evt_field_timestamp(&jsonFmtRemain, timestamp);
                break;
            case EVT_FIELD_EVENT_ID:
                ret = fill_evt_field_eventId(&jsonFmtRemain, eventId);
                break;
            case EVT_FIELD_ATTRIBUTES:
                ret = fill_evt_field_attrs(&jsonFmtRemain, entityId, eventId);
                break;
            case EVT_FIELD_RESOURCE:
                ret = fill_evt_field_resource(&jsonFmtRemain, metricId, evtFields, mgr);
                break;
            case EVT_FIELD_SEVER_TXT:
                ret = fill_log_field_simple(&jsonFmtRemain, &evtFields[EVT_ORIG_FIELD_SEVER_TXT],
                                            gEvtField[EVT_FIELD_SEVER_TXT], VAL_WITH_QUOTE);
                break;
            case EVT_FIELD_SEVER_NO:
                ret = fill_log_field_simple(&jsonFmtRemain, &evtFields[EVT_ORIG_FIELD_SEVER_NO],
                                            gEvtField[EVT_FIELD_SEVER_NO], VAL_WITHOUT_QUOTE);
                break;
            case EVT_FIELD_BODY:
                ret = fill_log_field_simple(&jsonFmtRemain, &evtFields[EVT_ORIG_FIELD_BODY],
                                            gEvtField[EVT_FIELD_BODY], VAL_WITH_QUOTE);
                break;
            default:
                ret = -1;
        }
        if (ret) {
            return -1;
        }

        if (fieldNo != EVT_FIELD_MAX - 1) {
            if (strbuf_append_chr_with_check(&jsonFmtRemain, ',')) {
                error_evt2json_buffer_no_enough_space();
                return -1;
            }
        }
    }

    if (strbuf_append_str_with_check(&jsonFmtRemain, "}\0", 2)) {
        error_log2json_buffer_no_enough_space();
        return -1;
    }

    return 0;
}
