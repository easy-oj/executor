cmake_minimum_required(VERSION 3.5)
project(executor C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXE_LINKER_FLAGS "-static -pthread")

link_libraries(rt)
link_libraries(pthread)

add_executable(executor main.c main.h)
