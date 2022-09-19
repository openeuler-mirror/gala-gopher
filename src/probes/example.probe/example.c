#include <stdio.h>
#include <string.h>
#include "args.h"
#include "nprobe_fprintf.h"

void example_collect_data()
{
    nprobe_fprintf(stdout, "|%s|%s|%s|%s|%s|\n",
        "example",
        "system",
        "10",
        "88",
        "15"
    );
}

int main(struct probe_params * params)
{
    example_collect_data();
    return 0;
}

