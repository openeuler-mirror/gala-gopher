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
 * Author: yangyongguang
 * Create: 2023-10-13
 * Description: gopher json tool
 ******************************************************************************/

#ifndef GOPHER_JSON_TOOL_H
#define GOPHER_JSON_TOOL_H



#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "limits.h"

#define INVALID_INT_NUM (-INT_MAX)
#define JSON_OTHER (1 << 0)
#define JSON_NUMBER (1 << 1)
#define JSON_STRING (1 << 2)
#define JSON_ARRAY (1 << 3)
#define JSON_ERROR (1 << 4)

struct key_value {
    char *key;
    const void *valuePtr;
};

struct key_value_pairs {
    struct key_value *kv_pairs;
    unsigned int len; // value pair length
};

void* Json_Parse(const char *probe_content);
void *Json_GetObjectItem(const void *jsonObj, const char *keyStr);

/* string relative */
unsigned char Json_IsEmptyString(const void *jsonObj);

/***
 * if is list -> get {"": v1, "": v2, "": v3} etc.
 * if is object pair -> get {k1:v1, k2:v2, k3:v3} etc.
***/
struct key_value_pairs* Json_GetKeyValuePairs(const void *jsonObj);

void Json_DeleteKeyValuePairs(struct key_value_pairs *kv_pairs);

/***
 * string do not need to be release.
 ***/
const char *Json_GetValueString(const void *jsonObj);

/* array relative */
unsigned int Json_GetArraySize(const void *jsonObj);
void *Json_GetArrayItem(const void *jsonObj, int i);

/* type function */
unsigned char Json_IsString(const void *jsonObj);
unsigned char Json_IsNumeric(const void *jsonObj);
unsigned char Json_IsObject(const void *jsonObj);
unsigned char Json_IsArray(const void *jsonObj);
unsigned char Json_IsBool(const void *jsonObj);

/***
 * brief return Number, Array, String, Other.
 ***/
int Json_GetType(const void *jsonObj);

/* get value */
int Json_GetValueInt(const void *jsonObj);
bool Json_GetValueBool(const void *jsonObj);

/***
 *  write json data relative
***/
/* as the same as create object */
void* Json_CreateArray(void);

void* Json_CreateObject(void);

void Json_AddStringToObject(void *jsonObj, const char *nameCStr, const char *valCStr);

void Json_AddItemToArray(void *jsonObj, void *item);

void Json_AddStringItemToArray(void *jsonObj, const char *valCStr);

void Json_AddUIntItemToArray(void *jsonObj, unsigned int valInt);

void Json_AddUIntItemToObject(void *jsonObj, const char *nameCStr, unsigned int valInt);

void Json_AddCharItemToObject(void *jsonObj, const char *nameCStr, char valChar);

void Json_AddItemToObject(void *jsonObj, const char *nameCStr, void *item);

/***
 * json memory delete
***/
void Json_Delete(void *jsonObj);

/*** special function ***/
/***
 * For each function for iter object or array of which has at least one element.
 * element is new object, so it should be release by hand, using Json_Delete function.
 ***/
#define Json_ArrayForEach(kv, kv_pairs) \
    for (int idx = 0; idx < (kv_pairs)->len && ((kv) = &(kv_pairs)->kv_pairs[idx]); ++idx)

#define CHECK_STRING_INPUT(inputStr) (!inputStr)

char *Json_PrintUnformatted(void *jsonObj);

#ifdef __cplusplus
}
#endif

#endif  // GOPHER_JSON_TOOL_H
