#ifndef __VMLINUX_H_ENTRY__
#define __VMLINUX_H_ENTRY__

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_x86_64.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_aarch64.h"
#endif

#endif