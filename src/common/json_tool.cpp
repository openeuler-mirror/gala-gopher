#include "json_tool.h"
#include <json/json.h>
#include <string>
#include <cstring>
#include <cstdlib>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(disable : 4996)
#endif
/***
 * this root point ptr should release, after use.
***/
void* Json_Parse(const char *probe_content)
{
    if (!probe_content) {
        return nullptr;
    }
    Json::Reader reader;
    auto *root = new Json::Value();
    std::string str(probe_content);
    if (reader.parse(str, *root)) {
        return (void*)(root);
    } else {
        delete root;
        return nullptr;
    }
}

void *Json_GetObjectItem(const void *jsonObj, const char *keyStr)
{
    if ((!jsonObj) or CHECK_STRING_INPUT(keyStr)) {
        return nullptr;
    }
    const std::string &keyString = std::string(keyStr);
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    if (jsObj->isMember(keyString)) {
        return (void*)&((*jsObj)[keyString]);
    } else {
        return nullptr;
    }
}

unsigned char Json_IsString(const void *jsonObj)
{
    if (!jsonObj) {
        return 0;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    bool ret = jsObj->isString();
    return ret;
}

unsigned char Json_IsBool(const void *jsonObj)
{
    if (!jsonObj) {
        return 0;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    bool ret = jsObj->isBool();
    return ret;
}

unsigned char Json_IsNumeric(const void *jsonObj)
{
    if (!jsonObj) {
        return 0;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    bool ret = jsObj->isNumeric();
    return ret;
}

unsigned char Json_IsObject(const void *jsonObj)
{
    if (!jsonObj) {
        return 0;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    bool ret = jsObj->isObject();
    return ret;
}

unsigned char Json_IsArray(const void *jsonObj)
{
    if (!jsonObj) {
        return 0;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    bool ret = jsObj->isArray();
    return ret;
}

int Json_GetType(const void *jsonObj)
{
    if (!jsonObj) {
        return JSON_ERROR;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    int type = static_cast<int>(jsObj->type());
    if (type == Json::ValueType::stringValue) {
        return JSON_STRING;
    } else if (type == Json::ValueType::arrayValue) {
        return JSON_ARRAY;
    } else if ((type == Json::ValueType::intValue) or (type == Json::ValueType::uintValue) or
        (type == Json::ValueType::realValue) or (type == Json::ValueType::booleanValue)) {
        return JSON_NUMBER;
    } else {
        return JSON_OTHER;
    }
}

unsigned char Json_IsEmptyString(const void *jsonObj)
{
    if (!jsonObj) {
        return 1U;  // return is empty, true.
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    const std::string strValue = jsObj->asString();
    return strValue.empty();
}

const char *Json_GetValueString(const void *jsonObj)
{
    if (!jsonObj) {
        return nullptr;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    const char *begin;
    __attribute__((unused)) const char *end;
    const bool getRet = jsObj->getString(&begin, &end);
    if (getRet) {
        return begin;
    } else {
        return nullptr;
    }
}

bool Json_GetValueBool(const void *jsonObj)
{
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    return jsObj->asBool();
}

struct key_value_pairs* Json_GetKeyValuePairs(const void *jsonObj)
{
    if (!jsonObj) {
        return nullptr;
    }
    const Json::Value &jsObj = (*static_cast<const Json::Value *>(jsonObj));
    const size_t numElem = jsObj.size();
    auto *kv_pairs = (struct key_value_pairs*)malloc(sizeof(struct key_value_pairs));
    if (!kv_pairs) {
        return nullptr;
    }
    kv_pairs->len = 0;
    kv_pairs->kv_pairs = (struct key_value*)malloc(numElem * sizeof(struct key_value));
    if (!kv_pairs->kv_pairs) {
        free(kv_pairs);
        return nullptr;
    }
    for (Json::ValueConstIterator it = jsObj.begin(); it != jsObj.end(); ++it) {
        auto& kv = kv_pairs->kv_pairs[kv_pairs->len];
        kv.key = strdup(it.name().c_str());
        if (!kv.key) {
            goto err;
        }
        kv.valuePtr = (void *)(&(*it));
        ++kv_pairs->len;
    }
    return kv_pairs;
err:
    Json_DeleteKeyValuePairs(kv_pairs);
    return nullptr;
}

void Json_DeleteKeyValuePairs(struct key_value_pairs *kv_pairs)
{
    if (!kv_pairs) {
        return;
    }
    const size_t kv_len = kv_pairs->len;
    for (size_t idx = 0; idx < kv_len; ++idx) {
        free(kv_pairs->kv_pairs[idx].key);
    }
    free(kv_pairs->kv_pairs);
    free(kv_pairs);
}

unsigned int Json_GetArraySize(const void *jsonObj)
{
    if (!jsonObj) {
        return 0;  // return empty.
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    if (jsObj->isArray() or jsObj->isObject()) {
        return jsObj->size();
    } else {
        return 0;
    }
}


void *Json_GetArrayItem(const void *jsonObj, int i)
{
    if ((!jsonObj) or (i < 0)) {
        return nullptr;  // return empty.
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    if (!jsObj->isArray() && !jsObj->isObject()) {
        return nullptr;
    }
    const auto size = jsObj->size();
    if (static_cast<size_t>(i) >= size) {
        return nullptr;
    }
    return (void*)(&(*jsObj)[i]);
}

int Json_GetValueInt(const void *jsonObj)
{
    if (!jsonObj) {
        return INVALID_INT_NUM;
    }
    auto *jsObj = static_cast<const Json::Value *>(jsonObj);
    return jsObj->asInt();
}

void *Json_CreateArray()
{
    auto *root = new Json::Value(Json::arrayValue);
    return (void *)root;
}

void *Json_CreateObject()
{
    auto *root = new Json::Value(Json::objectValue);
    return (void *)root;
}

void Json_AddStringToObject(void *jsonObj, const char *nameCStr, const char *valCStr)
{
    if ((!jsonObj) or CHECK_STRING_INPUT(nameCStr) or CHECK_STRING_INPUT(valCStr)) {
        return;
    }
    const std::string &nameStr = std::string(nameCStr);
    const std::string &valueStr = std::string(valCStr);
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    (*jsObj)[nameStr] = valueStr;
}

void Json_AddItemToArray(void *jsonObj, void *item)
{
    if ((!jsonObj) or !(item)) {
        return;
    }
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    auto *itemObj = static_cast<Json::Value *>(item);
    jsObj->append((*itemObj));
}

void Json_AddStringItemToArray(void *jsonObj, const char *valCStr)
{
    if ((!jsonObj) or CHECK_STRING_INPUT(valCStr)) {
        return;
    }
    const std::string &valueStr = std::string(valCStr);
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    jsObj->append(valueStr);
}

void Json_AddUIntItemToArray(void *jsonObj, unsigned int valInt)
{
    if (!jsonObj) {
        return;
    }
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    jsObj->append(valInt);
}

void Json_AddUIntItemToObject(void *jsonObj, const char *nameCStr, unsigned int valInt)
{
    if (!jsonObj or CHECK_STRING_INPUT(nameCStr)) {
        return;
    }
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    const std::string &nameStr = std::string(nameCStr);
    (*jsObj)[nameStr] = valInt;
}

void Json_AddCharItemToObject(void *jsonObj, const char *nameCStr, char valChar)
{
    if (!jsonObj or CHECK_STRING_INPUT(nameCStr)) {
        return;
    }
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    const std::string &nameStr = std::string(nameCStr);
    (*jsObj)[nameStr] = valChar;
}

void Json_AddItemToObject(void *jsonObj, const char *nameCStr, void *item)
{
    if (!jsonObj or CHECK_STRING_INPUT(nameCStr)) {
        return;
    }
    const std::string &nameStr = std::string(nameCStr);
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    auto *itemObj = static_cast<Json::Value *>(item);
    (*jsObj)[nameStr] = (*itemObj);
}

void Json_Delete(void *jsonObj)
{
    if (!jsonObj) {
        return;
    }
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    delete jsObj;
}

char *Json_PrintUnformatted(void *jsonObj)
{
    if (!jsonObj) {
        return nullptr;
    }
    auto *jsObj = static_cast<Json::Value *>(jsonObj);
    Json::FastWriter writer;
    std::string strJson = writer.write(*jsObj);
    char *res = strdup(strJson.c_str());
    if (!res) {
        return nullptr;
    }
    return res;
}
