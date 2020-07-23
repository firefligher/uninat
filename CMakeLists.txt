cmake_minimum_required (VERSION 3.8)

project ("UniNAT")

# Collecting the sources files

file(GLOB UniNAT_HEADERS ${PROJECT_SOURCE_DIR}/src/*.h)
file(GLOB UniNAT_SOURCES ${PROJECT_SOURCE_DIR}/src/*.c)

set(UniNAT_ALL_SOURCES ${UniNAT_HEADERS} ${UniNAT_SOURCES})

# Adding the executable

add_executable (UniNAT ${UniNAT_ALL_SOURCES})

# Linking libraries

target_link_libraries(UniNAT pthread netfilter_queue nfnetlink)
