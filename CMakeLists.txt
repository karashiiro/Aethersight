cmake_minimum_required(VERSION 3.17)
project(Aethersight)

set(CMAKE_CXX_STANDARD 20)
add_compile_definitions(DLIBTINS_ENABLE_CXX11)
add_compile_definitions(TINS_STATIC)

# Define library target
set(src include/Aethersight/Network/CommonNetwork.h src/Decompress.h src/Decompress.cpp include/Aethersight/Aethersight.h src/Aethersight.cpp)
add_library(aethersight-static ${src})
add_library(aethersight-shared SHARED ${src})
add_executable(aethersight-cli src/main.cpp)
set_target_properties(aethersight-static PROPERTIES OUTPUT_NAME libaethersight)
set_target_properties(aethersight-shared PROPERTIES OUTPUT_NAME Aethersight)
set_target_properties(aethersight-cli PROPERTIES OUTPUT_NAME aethersight)

# Define include directory
target_include_directories(aethersight-static PRIVATE include)
target_include_directories(aethersight-shared PRIVATE include)
target_include_directories(aethersight-cli PRIVATE include)

# Target link libraries
set(tins ${CMAKE_SOURCE_DIR}/lib/tins.lib)
set(zlib ${CMAKE_SOURCE_DIR}/lib/zlib.lib)
set(win_lib ${CMAKE_SOURCE_DIR}/lib/wpcap.lib Ws2_32.lib Iphlpapi.lib)

target_link_libraries(aethersight-static PRIVATE ${tins} ${zlib})
target_link_libraries(aethersight-shared PRIVATE ${tins} ${win_lib} ${zlib})
target_link_libraries(aethersight-cli PRIVATE aethersight-static ${tins} ${win_lib} ${zlib})