# 这是一个示例的 FindGlibc.cmake 文件，用于查找 glibc
find_library(GLIB_C_LIBRARY NAMES c)
mark_as_advanced(GLIB_C_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Glibc DEFAULT_MSG GLIB_C_LIBRARY)
