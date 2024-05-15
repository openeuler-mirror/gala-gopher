CMAKE_MINIMUM_REQUIRED(VERSION 3.5.2)
unset(FLAMEGRAPH_SVG)
set(CMAKE_VERBOSE_MAKEFILE ON)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++")

PROJECT(gala-gopher)

MESSAGE("ENV PROBES_LIST:\n"  ${PROBES_LIST})
MESSAGE("ENV PROBES_C_LIST:\n"  ${PROBES_C_LIST})
MESSAGE("ENV PROBES_META_LIST:\n"  ${PROBES_META_LIST})
MESSAGE("ENV LIBBPF_VER_MAJOR:\n"  ${LIBBPF_VER_MAJOR})
MESSAGE("ENV LIBBPF_VER_MINOR:\n"  ${LIBBPF_VER_MINOR})

SET(EXECUTABLE_OUTPUT_PATH ../../../)
SET(EXECUTABLE_TARGET gala-gopher)
SET(EXECUTABLE_TARGET_CMD gopher-ctl)

SET(SRC_DIR         ../../src)
SET(BASE_DIR        ${SRC_DIR}/lib)
SET(RESOURCE_DIR    ${SRC_DIR}/resource)
SET(CONFIG_DIR      ${SRC_DIR}/lib/config)
SET(EGRESS_DIR      ${SRC_DIR}/egress)
SET(INGRESS_DIR     ${SRC_DIR}/ingress)
SET(WEB_SERVER_DIR  ${SRC_DIR}/web_server)
SET(FIFO_DIR        ${SRC_DIR}/lib/fifo)
SET(META_DIR        ${SRC_DIR}/lib/meta)
SET(PROBE_DIR       ${SRC_DIR}/lib/probe)
SET(IMDB_DIR        ${SRC_DIR}/lib/imdb)
SET(COMMON_DIR      ${SRC_DIR}/common)
SET(RESTAPI_DIR     ${SRC_DIR}/api)
SET(HTTPSERVER_DIR  ${SRC_DIR}/lib/http_server)
SET(EBPF_PROBE_DIR  ${SRC_DIR}/probes/extends/ebpf.probe)
SET(CMD_DIR         ${SRC_DIR}/cmd)

SET(LIBELF_DIR /usr/include/libelf)

SET(CMAKE_C_FLAGS "-rdynamic -std=gnu11 -g -Wl,-z,relro,-z,now -DNATIVE_PROBE_FPRINTF \
    -DPROBES_LIST=\"${PROBES_LIST}\" \
    -DLIBBPF_VER_MAJOR=\"${LIBBPF_VER_MAJOR}\" -DLIBBPF_VER_MINOR=\"${LIBBPF_VER_MINOR}\" "
)
SET(CMAKE_CXX_FLAGS "-rdynamic -std=c++11 -g -Wl,-z,relro,-z,now -DNATIVE_PROBE_FPRINTF")

find_package(jsoncpp REQUIRED)
message("FOUND CONFIG: ${jsoncpp_CONFIG}")
get_target_property(JSON_INC_PATH jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
include_directories(${JSON_INC_PATH})

message("JSON_INC_PATH: ${JSON_INC_PATH}")
link_libraries(${JSONCPP_LIBRARIES})

SET(SOURCES main.c daemon.c
    ${RESOURCE_DIR}/resource.c
    ${CONFIG_DIR}/config.c
    ${EGRESS_DIR}/egress.c
    ${INGRESS_DIR}/ingress.c
    ${INGRESS_DIR}/event2json.c

    ${FIFO_DIR}/fifo.c
    ${META_DIR}/meta.c
    ${HTTPSERVER_DIR}/http_server.c

    ${PROBE_DIR}/probe.c
    ${PROBE_DIR}/extend_probe.c
    ${PROBE_DIR}/pod_mng.c
    ${PROBE_DIR}/probe_mng.c
    ${PROBE_DIR}/snooper.c
    ${PROBE_DIR}/probe_params_parser.c
    ${PROBE_DIR}/ext_label.c
    ${IMDB_DIR}/imdb.c
    ${IMDB_DIR}/metrics.c
    ${IMDB_DIR}/container_cache.c

    ${COMMON_DIR}/container.c
    ${COMMON_DIR}/util.c
    ${COMMON_DIR}/event.c
    ${COMMON_DIR}/logs.c
    ${COMMON_DIR}/json_tool.cpp
    ${COMMON_DIR}/gopher_elf.c
    ${COMMON_DIR}/kern_symb.c
    ${COMMON_DIR}/ipc.c
    ${COMMON_DIR}/strbuf.c
    ${COMMON_DIR}/histogram.c
    ${COMMON_DIR}/core_btf.c

    ${WEB_SERVER_DIR}/web_server.c
    ${RESTAPI_DIR}/rest_server.c
    ${EBPF_PROBE_DIR}/src/lib/java_support.c

    ${CMD_DIR}/cmd_common.c
    ${CMD_DIR}/cmd_server.c
)

SET(SOURCES_CMD
    ${COMMON_DIR}/logs.c
    ${CMD_DIR}/cmd_common.c
    ${CMD_DIR}/cmd_client.c
)

FOREACH(FILE ${PROBES_C_LIST})
    SET(SOURCES ${SOURCES} ${FILE})
ENDFOREACH()

if("${GOPHER_DEBUG}" EQUAL 1)
add_definitions(-DGOPHER_DEBUG)
endif()

execute_process(
    COMMAND bash "-c" "echo -n $(git rev-parse --short HEAD 2>/dev/null)"
    OUTPUT_VARIABLE GOPHER_COMMIT_SHA1
)

if(GOPHER_COMMIT_SHA1)
add_definitions(-DGOPHER_COMMIT_SHA1="${GOPHER_COMMIT_SHA1}")
endif()

SET(INC_DIRECTORIES
    ${BASE_DIR}
    ${RESOURCE_DIR}
    ${CONFIG_DIR}
    ${EGRESS_DIR}
    ${INGRESS_DIR}
    ${WEB_SERVER_DIR}
    ${RESTAPI_DIR}

    ${FIFO_DIR}
    ${META_DIR}

    ${PROBE_DIR}
    ${IMDB_DIR}
    ${LIBRDKAFKA_DIR}
    ${LIBELF_DIR}

    ${COMMON_DIR}
    ${JSON_INC_PATH}
    ${HTTPSERVER_DIR}
    ${EBPF_PROBE_DIR}/src/include

    ${CMD_DIR}
)

SET(LINK_LIBRARIES config pthread rt dl bpf elf jsoncpp_lib ssl event event_openssl crypto)

add_definitions(${BUILD_OPTS})

if(${BUILD_OPTS} MATCHES "-DKAFKA_CHANNEL")
    SET(KAFKA_DIR ${SRC_DIR}/lib/kafka)
    SET(SOURCES ${SOURCES} ${KAFKA_DIR}/kafka.c)
    SET(INC_DIRECTORIES ${INC_DIRECTORIES}  ${KAFKA_DIR})
    SET(LINK_LIBRARIES ${LINK_LIBRARIES} rdkafka)
endif()

MESSAGE("SOURCES:\n" ${SOURCES})
ADD_EXECUTABLE(${EXECUTABLE_TARGET} ${SOURCES})
TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET} PRIVATE ${INC_DIRECTORIES})
TARGET_LINK_LIBRARIES(${EXECUTABLE_TARGET} PRIVATE ${LINK_LIBRARIES})

ADD_EXECUTABLE(${EXECUTABLE_TARGET_CMD} ${SOURCES_CMD})
TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET_CMD} PRIVATE ${INC_DIRECTORIES})