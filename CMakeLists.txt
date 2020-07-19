cmake_minimum_required (VERSION 3.8)

project ("UniNAT")

# Collecting the sources files

file(GLOB_RECURSE UniNAT_SOURCES ${PROJECT_SOURCE_DIR}/src *.c *.h)

# Adding the executable

add_executable (UniNAT ${UniNAT_SOURCES})

# Linking libraries

target_link_libraries(UniNAT pthread)
