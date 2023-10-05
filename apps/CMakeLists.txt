add_library(lunar-s lunar-streaming/lunar_s.c)
target_link_libraries(lunar-s PUBLIC insane "-lm" "dl")

add_executable(s-client lunar-streaming/s_client.c)
target_link_libraries(s-client lunar-s)

add_executable(s-server lunar-streaming/s_server.c)
target_link_libraries(s-server lunar-s)

add_executable(sendfile lunar-streaming/sendfile.c)
target_link_libraries(sendfile PUBLIC lunar-s "rt")
add_executable(recvfile lunar-streaming/recvfile.c)
target_link_libraries(recvfile PUBLIC lunar-s "rt")

add_library(lunar lunar/lunar.c)
add_subdirectory(lunar)
target_link_libraries(lunar PUBLIC insane "-lm" "dl")

add_executable(lpub lunar/lunar_pub.c)
target_link_libraries(lpub PUBLIC lunar "rt")

add_executable(lsub lunar/lunar_sub.c)
target_link_libraries(lsub PUBLIC lunar "rt")

add_executable(lunar-perftest lunar/lunar_perftest.c)
target_link_libraries(lunar-perftest PUBLIC lunar "-lm" "rt" "dl")

# add_subdirectory(gstreamer)