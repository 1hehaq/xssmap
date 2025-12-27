cmake_minimum_required(VERSION 3.10)
project(xssmap C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -pthread")

find_package(CURL REQUIRED)

add_executable(xssmap
    src/main.c
    src/scanner.c
    src/http.c
    src/utils.c
    src/techniques/domparser.c
    src/techniques/scriptinj.c
    src/techniques/eventhand.c
    src/techniques/attrbreak.c
    src/techniques/taginj.c
    src/techniques/uriinj.c
    src/techniques/dombreak.c
    src/techniques/verify.c
    src/techniques/popup.c
    src/techniques/svgmath.c
    src/techniques/advanced.c
)

target_include_directories(xssmap PRIVATE 
    ${CURL_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/lib
)

target_link_libraries(xssmap 
    ${CURL_LIBRARIES} 
    pthread
    ${CMAKE_SOURCE_DIR}/lib/liblexbor_static.a
    m
)

install(TARGETS xssmap DESTINATION bin)

add_executable(benchmark
    benchmark.c
    src/techniques/domparser.c
    src/techniques/scriptinj.c
    src/techniques/eventhand.c
    src/techniques/attrbreak.c
    src/techniques/taginj.c
    src/techniques/uriinj.c
    src/techniques/dombreak.c
    src/techniques/verify.c
    src/techniques/popup.c
    src/techniques/svgmath.c
    src/techniques/advanced.c
)

target_include_directories(benchmark PRIVATE 
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/lib
)

target_link_libraries(benchmark
    ${CMAKE_SOURCE_DIR}/lib/liblexbor_static.a
    m
)
