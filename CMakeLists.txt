cmake_minimum_required(VERSION 3.5)

project(Combined_QUIC)

set (make_db_sou
    src/fp_db/main_make_db.cpp
    src/fp_db/fp_sub_db.cpp
)

set (quic_sou
    src/quic/main_quic.cpp
)


add_executable(make_db ${make_db_sou})
add_executable(QUIC_data ${quic_sou})
target_include_directories(make_db PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(QUIC_data PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(make_db ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a)
target_link_libraries(make_db ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a )
target_link_libraries(QUIC_data ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a )
target_link_libraries(QUIC_data ${PROJECT_SOURCE_DIR}/lib/win/lib_QUIC_SE.a)
target_link_libraries(QUIC_data ${PROJECT_SOURCE_DIR}/lib/win/libFlow2SE.a )
target_link_libraries(QUIC_data ${PROJECT_SOURCE_DIR}/lib/win/libPcapSE.a )
target_link_libraries(QUIC_data ${PROJECT_SOURCE_DIR}/lib/win/libPacketSE.a )
target_link_libraries(QUIC_data ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a)
