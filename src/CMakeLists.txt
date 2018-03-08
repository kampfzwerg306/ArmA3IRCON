cmake_minimum_required (VERSION 3.0)

set(INTERCEPT_CLIENT_PATH "${PROJECT_SOURCE_DIR}/dependency/intercept/src/client")

set(INTERCEPT_INCLUDE_PATH "${INTERCEPT_CLIENT_PATH}/headers" "${INTERCEPT_CLIENT_PATH}/headers/client/" "${INTERCEPT_CLIENT_PATH}/headers/client/sqf")


if(USE_64BIT_BUILD)
    set(ZOMBIE_NAME "rcon_x64")
else()
    set(ZOMBIE_NAME "rcon")
endif()


add_definitions(/DINTERCEPT_NO_THREAD_SAFETY)
add_definitions(/DNOMINMAX)
add_definitions(/DINTERCEPT_SQF_STRTYPE_RSTRING)
add_definitions(/D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS) #No I don't cheat!

#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/rv/${ZOMBIE_NAME}/intercept")

file(GLOB INTERCEPT_SOURCES "${INTERCEPT_CLIENT_PATH}/intercept/client/*.cpp"  "${INTERCEPT_CLIENT_PATH}/intercept/client/sqf/*.cpp" "${INTERCEPT_CLIENT_PATH}/intercept/shared/*.cpp")
SOURCE_GROUP("intercept" FILES ${INTERCEPT_SOURCES})


file(GLOB_RECURSE UTIL_SOURCES "${PROJECT_SOURCE_DIR}/dependency/utils/*.cpp")
SOURCE_GROUP("utils" FILES ${UTIL_SOURCES})
set(UTILS_INCLUDES "${PROJECT_SOURCE_DIR}/dependency/utils")

file(GLOB_RECURSE ZOMBIE_SOURCES src/*.*pp)
SOURCE_GROUP("src" FILES ${ZOMBIE_SOURCES})

#only needed if standalone compile
#file(GLOB_RECURSE REST_SOURCES "${PROJECT_SOURCE_DIR}/dependency/rest/src/rest/*est*.*pp" "${PROJECT_SOURCE_DIR}/rest/src/restbed/source/*.*pp")
#SOURCE_GROUP("rest" FILES ${REST_SOURCES})

set(library_sources ${ZOMBIE_SOURCES} ${REST_SOURCES})

add_library( ${ZOMBIE_NAME} SHARED ${library_sources} ${INTERCEPT_SOURCES} ${UTIL_SOURCES})

target_link_libraries(${ZOMBIE_NAME} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${ZOMBIE_NAME} ${LINK_LIBS})

set_target_properties(${ZOMBIE_NAME} PROPERTIES PREFIX "")
set_target_properties(${ZOMBIE_NAME} PROPERTIES FOLDER rcon)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR} 
	${INTERCEPT_INCLUDE_PATH} 
	${UTILS_INCLUDES}
	"${PROJECT_SOURCE_DIR}/dependency/rest/src"
	"${PROJECT_SOURCE_DIR}/dependency/rest/src/rest"
	"${PROJECT_SOURCE_DIR}/dependency/asio/asio/include"
	"${PROJECT_SOURCE_DIR}/dependency/rest/src/restbed/dependency/asio/asio/include"
	"${PROJECT_SOURCE_DIR}/dependency/rest/src/restbed/dependency/catch/include"
	"${PROJECT_SOURCE_DIR}/dependency/rest/src/restbed/dependency/kashmir"
	"${PROJECT_SOURCE_DIR}/dependency/rest/src/restbed/source"	
	"${PROJECT_SOURCE_DIR}/dependency/rest/src/restbed"
)
if(CMAKE_COMPILER_IS_GNUCXX)
	SET(CMAKE_CXX_FLAGS "-std=c++1z -O2 -s -fPIC -fpermissive -static-libgcc -static-libstdc++ -march=i686 -m32")
	set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
	set(CMAKE_SHARED_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")
else()
	set(CMAKE_CXX_FLAGS_DEBUG "/D _DEBUG /MDd /Zi /Ob0 /Od /RTC1 /MP /EHsc")
	set(CMAKE_CXX_FLAGS_RELEASE "/MD /Zi /O2 /Ob1 /EHsc /MP") #with debug info
	set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "/OPT:REF /DEBUG:FULL") 
endif()


if(CMAKE_COMPILER_IS_GNUCXX)
	set_target_properties(${INTERCEPT_NETWORK_NAME} PROPERTIES LINK_SEARCH_START_STATIC 1)
	set_target_properties(${INTERCEPT_NETWORK_NAME} PROPERTIES LINK_SEARCH_END_STATIC 1)
endif()
