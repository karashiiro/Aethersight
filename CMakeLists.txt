cmake_minimum_required(VERSION 3.17)
project(Aethersight)

set(CMAKE_CXX_STANDARD 20)
add_compile_definitions(DLIBTINS_ENABLE_CXX11)
add_compile_definitions(TINS_STATIC)

# Define library target
add_executable(aethersight src/main.cpp src/CommonNetwork.h src/Decompress.h src/Decompress.cpp src/Aethersight.h src/Aethersight.cpp)

# Define include directory
target_include_directories(aethersight PRIVATE include)

# Target link libraries
set(tins ${CMAKE_SOURCE_DIR}/lib/tins.lib)
set(zlib ${CMAKE_SOURCE_DIR}/lib/zlib.lib)
set(win_lib ${CMAKE_SOURCE_DIR}/lib/wpcap.lib Ws2_32.lib Iphlpapi.lib)

target_link_libraries(aethersight PRIVATE ${tins} ${win_lib} ${zlib})