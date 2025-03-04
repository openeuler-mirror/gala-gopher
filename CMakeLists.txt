cmake_minimum_required(VERSION 3.10)
project(sysTrace VERSION 1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置输出目录
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 添加源文件
set(SRC_FILES
    src/init.c
    src/cann_hook.c
    src/libc_hook.c
)

# 生成动态库
add_library(libsystrace SHARED ${SRC_FILES})

# 安装动态库
install(TARGETS libsystrace LIBRARY DESTINATION lib)
