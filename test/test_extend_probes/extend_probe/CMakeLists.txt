CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++")
PROJECT(gala-gopher-extend-test)
SET(EXECUTABLE_TARGET extend_probe_test)

MESSAGE("ENV PROBES_LIST: \n" ${PROBES_LIST})
MESSAGE("ENV PROBES_C_LIST: \n" ${PROBES_C_LIST})
MESSAGE("ENV PROBES_META_LIST: \n" ${PROBES_META_LIST})


SET(SRC_DIR                 ${CMAKE_CURRENT_SOURCE_DIR}/../../../src)
SET(COMMON_SRC_DIR          ${SRC_DIR}/common)

message("[INFO] SRC_DIR:    ${SRC_DIR}")
SET(PROBE_LISTS             endpointprobe tcpprobe)
SET(LIB_PROBE_PATH          ${SRC_DIR}/lib/probe)
SET(EXTEND_PROBE_BD         ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/probes/extends/ebpf.probe/src)
SET(SRC_LIB_PROBE_DIR       ${SRC_DIR}/lib/probe)
SET(EBPF_PROBE_DIR          ${SRC_DIR}/probes/extends/ebpf.probe)

set (BUILD_PROBE_NODE 1)
if (DEFINED BUILD_PROBE_NODE)
    foreach (OBJ_PATH ${PROBE_LISTS})
        SET(CURR_PROBE_DB             ${EXTEND_PROBE_BD}/${OBJ_PATH})
        message("CURR_PROBE_DB: ${CURR_PROBE_DB}")
        file(GLOB BEFORE_SOURCES "${CURR_PROBE_DB}/*")
        execute_process(COMMAND "make"
                WORKING_DIRECTORY ${CURR_PROBE_DB}
                RESULT_VARIABLE result)
        if (NOT result EQUAL 0)
            message(FATAL_ERROR "error code: ${result}")
        endif()

        file(GLOB AFTER_SOURCES "${CURR_PROBE_DB}/*")
        foreach (file_elem ${BEFORE_SOURCES})
            list(REMOVE_ITEM AFTER_SOURCES ${file_elem})
        endforeach ()
        message("[FILES]: NEW FILE LIST \n ${AFTER_SOURCES}")

        set(DEST_BD ${CMAKE_CURRENT_BINARY_DIR})
        foreach (gen_file_elem ${AFTER_SOURCES})
            get_filename_component(src ${gen_file_elem} ABSOLUTE)
            get_filename_component(name_we ${gen_file_elem} NAME_WE)
            get_filename_component(ext ${gen_file_elem} EXT)
            # set(dest ${DEST_BD}/${name_we}${ext})
            set(dest ${DEST_BD})
            message("src: ${src}  => ${dest}")
            execute_process(COMMAND "mv" "${src}" "${dest}"  # sep command.
                    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                    RESULT_VARIABLE result
                    ERROR_VARIABLE error_output)
            if(NOT result EQUAL 0)
                message(FATAL_ERROR "Failed to move file from ${src} to ${dest}. Error code: ${result}\nError output: ${error_output}")
            endif()
        endforeach ()

        # make clean
        execute_process(COMMAND "make" "clean"
                WORKING_DIRECTORY ${CURR_PROBE_DB}
                RESULT_VARIABLE result)
        if (NOT result EQUAL 0)
            message(FATAL_ERROR "error code make clean: ${result}, ${OBJ_PATH}")
        endif()
    endforeach ()
endif ()

# FOR DEBUG CODE
include_directories(/usr/include/)
include_directories(/usr/include/CUnit/)

# add execute cmake list
SET(LINK_LIBRARIES cunit)
SET(INC_DIRECTORIES
    ${COMMON_SRC_DIR}
    ${LIB_PROBE_PATH}
    ${SRC_LIB_PROBE_DIR}
    ${SRC_DIR}/lib
    ${SRC_DIR}/lib/fifo
    )

INCLUDE_DIRECTORIES(common_interface)

SET(SOURCE extend_tcp_endpoint_llt.c
        ${COMMON_SRC_DIR}/util.c
        ${COMMON_SRC_DIR}/logs.c
        ${COMMON_SRC_DIR}/ipc.c
        common_interface/common_interface.c
        test_endpoint.c
        test_tcp.c)

message("LIB_PROBE_PATH: ${LIB_PROBE_PATH}")
ADD_EXECUTABLE(${EXECUTABLE_TARGET} ${SOURCE})
TARGET_INCLUDE_DIRECTORIES(${EXECUTABLE_TARGET} PRIVATE ${INC_DIRECTORIES})
TARGET_LINK_LIBRARIES(${EXECUTABLE_TARGET} PRIVATE ${LINK_LIBRARIES})
message("[INFO] FINISHED EXTEND PROBE TEST CMakeLists.txt")
