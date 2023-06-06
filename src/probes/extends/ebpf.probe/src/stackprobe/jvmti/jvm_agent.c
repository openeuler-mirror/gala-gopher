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
 * Author: wo_cow
 * Create: 2022-12-09
 * Description: JVMTI agent
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <jvmti.h>

#define COMMAND_LEN             256
#define LINE_BUF_LEN            512
#define MAX_ARGS_NUM            4
#define ARGS_BUF_LEN            128
#define JAVA_SYM_FILE           "java-symbols.bin"

#ifndef __u64
typedef long long unsigned int __u64;
typedef __u64 u64;
#endif

int g_agent_attached = 0;
static FILE *g_sym_fp = NULL;


jint open_tmp_file(const char* options) {
    if (options == NULL) {
        return JNI_ERR;
    }
    if (g_sym_fp != NULL) {
        return JNI_OK;
    }
    if (access(options, F_OK) != 0) {
        FILE *fp;
        char command[COMMAND_LEN];
        command[0] = 0;
        (void)snprintf(command, COMMAND_LEN, "/usr/bin/mkdir -p %s", options);
        fp = popen(command, "r");
        if (fp != NULL) {
            (void)pclose(fp);
        }
    }
    char sym_tmp_path[LINE_BUF_LEN];
    sym_tmp_path[0] = 0;
    (void)snprintf(sym_tmp_path, LINE_BUF_LEN, "%s/%s", options, JAVA_SYM_FILE);

    g_sym_fp = fopen(sym_tmp_path, "a+");
    if (g_sym_fp == NULL) {
        printf("[JMI_AGENT]: open file failed.(%s)\n", sym_tmp_path);
    }

    return JNI_OK;
}

jint set_jvmti_caps(jvmtiEnv* jvmti) {
    jvmtiCapabilities cap;
    memset(&cap, 0, sizeof(jvmtiCapabilities));

    // cap.can_generate_object_free_events     = 1;
    // cap.can_generate_vm_object_alloc_events = 1;
    cap.can_get_line_numbers = 1;
    cap.can_get_source_file_name = 1;
    cap.can_generate_compiled_method_load_events = 1;

    jvmtiError error = (*jvmti)->AddCapabilities(jvmti, &cap);
    if (error != JVMTI_ERROR_NONE) {
        printf("[JMI_AGENT]: set jvmti caps failed\n");
        return JNI_ERR;
    }
    return JNI_OK;
}

jint set_notification_modes(jvmtiEnv* jvmti) {
    jvmtiError error;

    error = (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, (jthread)NULL);
    if (error != JVMTI_ERROR_NONE) {
        printf("[JMI_AGENT]: set notification mode for DynamicCodeGenerated failed.\n");
        return JNI_ERR;
    }

    error = (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, (jthread)NULL);
    if (error != JVMTI_ERROR_NONE) {
        printf("[JMI_AGENT]: set notification mode for CompiledMethodLoad failed.\n");
        return JNI_ERR;
    }

    return JNI_OK;
}

void deallocate(jvmtiEnv *jvmti, void *string) {
    if (string != NULL) (*jvmti)->Deallocate(jvmti, (unsigned char *) string);
}

void get_class_name_from_csig(char *dest, size_t dest_size, const char *sig) {
    if (sig[0] == 'L') {
        jint i;
        const char *src = sig + 1;
        for(i = 0; i < (dest_size - 1) && src[i]; i++) {
            char c = src[i];
            if (c == '/') c = '.';
            if (c == ';' || c == '$') break;
            dest[i] = c;
        }
        dest[i] = 0;
    } else {
        (void)snprintf(dest, dest_size, "%s", sig);
    }
}

static char __sym_tmp_str[COMMAND_LEN];
void write_sym(const void *code_addr, unsigned int code_size, char *csig, const char *method_name) {
    if (method_name == NULL) {
        return;
    }

    if (g_sym_fp != NULL) {
        __sym_tmp_str[0] = 0;
        if (csig != NULL) {
            char class_name[COMMAND_LEN];
            class_name[0] = 0;
            get_class_name_from_csig(class_name, sizeof(class_name), csig);
            (void)snprintf(__sym_tmp_str, COMMAND_LEN, "%llx %x %s::%s\n",
                (u64)code_addr, code_size, class_name, method_name);
        } else {
            (void)snprintf(__sym_tmp_str, COMMAND_LEN, "%llx %x %s\n",
                (u64)code_addr, code_size, method_name);
        }
        (void)fputs(__sym_tmp_str, g_sym_fp);
        (void)fflush(g_sym_fp);
    }
}

static void JNICALL cbCompiledMethodLoad(jvmtiEnv *jvmti, jmethodID method, jint code_size, const void* code_addr,
    jint map_length, const jvmtiAddrLocationMap* map, const void* compile_info) {
    jclass java_class;
    char* method_name;
    char* msig;
    char* csig;

    if (!(*jvmti)->GetMethodName(jvmti, method, &method_name, &msig, NULL) &&
        !(*jvmti)->GetMethodDeclaringClass(jvmti, method, &java_class) &&
        !(*jvmti)->GetClassSignature(jvmti, java_class, &csig, NULL)) {
        write_sym(code_addr, code_size, csig, method_name);
        deallocate(jvmti, method_name);
        deallocate(jvmti, msig);
        deallocate(jvmti, csig);
    }
}

void JNICALL cbDynamicCodeGenerated(jvmtiEnv *jvmti, const char* name, const void* address, jint length) {
    write_sym(address, length, NULL, name);
}

jint set_callbacks(jvmtiEnv* jvmti) {
    jvmtiEventCallbacks cb;
    memset(&cb, 0, sizeof(cb));

    // TODO: CompiledMethodUnload
    cb.CompiledMethodLoad = &cbCompiledMethodLoad;
    cb.DynamicCodeGenerated = &cbDynamicCodeGenerated;

    jvmtiError error = (*jvmti)->SetEventCallbacks(jvmti, &cb, sizeof(cb));
    if (error != JVMTI_ERROR_NONE) {
        printf("[JMI_AGENT]: Unable to attach CompiledMethodLoad callback.\n");
        return JNI_ERR;
    }
    g_agent_attached = 1;
    return JNI_OK;
}

// https://docs.oracle.com/en/java/javase/17/docs/specs/jvmti.html#GenerateEvents
jint get_missed_events(jvmtiEnv* jvmti) {
    jvmtiPhase phase;

    jvmtiError error = (*jvmti)->GetPhase(jvmti, &phase);
    if (error != JVMTI_ERROR_NONE) {
        printf("[JMI_AGENT]: Unable to get JVMTI phase.\n");
        return JNI_OK;
    }

    if (phase != JVMTI_PHASE_LIVE) {
        printf("[JMI_AGENT]: JVMTI not in live phase.\n");
        return JNI_OK;
    }

    (*jvmti)->GenerateEvents(jvmti, JVMTI_EVENT_COMPILED_METHOD_LOAD);
    (*jvmti)->GenerateEvents(jvmti, JVMTI_EVENT_DYNAMIC_CODE_GENERATED);

    return JNI_OK;
}

jint parse_args(char *options, char (*args)[ARGS_BUF_LEN]) {
    char *p = NULL;
    jint index = 0;

    if (options == NULL || args == NULL) {
        printf("[JMI_AGENT]: input args is NULL, please input tmp_file_path at least.\n");
        return JNI_ERR;
    }
    p = strtok(options, ",");
    while (p != NULL) {
        if (index >= MAX_ARGS_NUM) {
            break;
        }
        (void)snprintf(args[index++], ARGS_BUF_LEN, "%s", p);
        p = strtok(NULL, ",");
    }
    return JNI_OK;
}

jint JNICALL start(JavaVM *jvm, char *options, void *reserved) {
    static jvmtiEnv* jvmti = NULL;
    jint err;

    err = open_tmp_file(options);
    if (err != JNI_OK) {
        return err;
    }

    if (g_agent_attached) {
        return JNI_OK;
    }

    (*jvm)->GetEnv(jvm, (void **)&jvmti, JVMTI_VERSION_1);

    err = set_jvmti_caps(jvmti);
    if (err != JNI_OK) {
        return err;
    }
    err = set_notification_modes(jvmti);
    if (err != JNI_OK) {
        return err;
    }
    err = set_callbacks(jvmti);
    if (err != JNI_OK) {
        return err;
    }
    get_missed_events(jvmti);

    printf("[JMI_AGENT]: Agent OnAttach success\n");
    return JNI_OK;
}

jint JNICALL stop(void) {
    if (g_sym_fp != NULL) {
        (void)fclose(g_sym_fp);
        g_sym_fp = NULL;
    }
    return JNI_OK;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *jvm, char *options, void *reserved) {
    char args[MAX_ARGS_NUM][ARGS_BUF_LEN] = {0};

    if (parse_args(options, args) < 0) {
        printf("[JMI_AGENT]: parse args failed.\n");
        return JNI_ERR;
    }

    if (!strcmp(args[1], "stop")) {
        return stop();
    } else {
        return start(jvm, args[0], reserved);
    }
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM* jvm, char* options, void *reserved) {
    return Agent_OnAttach(jvm, options, NULL);
}