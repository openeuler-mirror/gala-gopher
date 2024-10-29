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
 * Author: algorithmofdish
 * Create: 2024-10-24
 * Description: the oom detector module
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include "tprofiling.h"
#include "oom_detector.h"

#define THRD_OOM_WEIGHT (0.1)

/* y = wx + b */
struct linear_model {
    double w;   /* 权重 */
    double b;   /* 偏移 */
};

/* 
 * 1. 若 size == 0，归一化失败
 * 2. 若最小值等于最大值，归一化失败
 */
int normalize_data(double data[], const int size)
{
    double min, max, diff;
    int i;

    if (size == 0) {
        return -1;
    }
    min = data[0];
    max = data[0];

    for (i = 1; i < size; ++i) {
        if (data[i] < min) {
            min = data[i];
        }
        if (data[i] > max) {
            max = data[i];
        }
    }

    if (min == max) {
        return -1;
    }
    diff = max - min;
    for (i = 0; i < size; ++i) {
        data[i] = (data[i] - min) / diff;
    }
    return 0;
}

struct linear_model least_square(const double x[], const double y[], const int size)
{
    struct linear_model model;
    double a = 0, b = 0, c = 0, d = 0;
    int i;

    for (i = 0; i < size; ++i) {
        a += x[i] * x[i];
        b += x[i];
        c += x[i] * y[i];
        d += y[i];
    }
    model.w = (c * size - b * d) / (a * size - b * b);
    model.b = (a * d - b * c) / (a * size - b * b);

    return model;
}

char is_mem_growing(double ts[], double mem_usage[], const int size)
{
    struct linear_model model;

    if (normalize_data(ts, size) || normalize_data(mem_usage, size)) {
        return 0;
    }

    model = least_square(ts, mem_usage, size);
    TP_DEBUG("linear model weight=%lf, bias=%lf\n", model.w, model.b);
    if (model.w > THRD_OOM_WEIGHT) {
        return 1;
    }
    return 0;
}