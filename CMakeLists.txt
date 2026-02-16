cmake_minimum_required(VERSION 3.16)
project(localdocsmd C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# OpenSSL for password hashing
find_package(OpenSSL REQUIRED)

# Source files
set(SOURCES
    src/main.c
    src/config.c
    src/database.c
    src/auth.c
    src/session.c
    src/rbac.c
    src/workspace.c
    src/project.c
    src/markdown.c
    src/server.c
    src/routes.c
    src/utils.c
    src/template.c
    vendor/mongoose.c
    vendor/cJSON.c
    vendor/md4c.c
    vendor/md4c-html.c
    vendor/entity.c
)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/vendor
    ${SQLITE3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME}
    ${SQLITE3_LIBRARIES}
    OpenSSL::Crypto
    pthread
)

# macOS specific
if(APPLE)
    target_link_libraries(${PROJECT_NAME} "-framework CoreFoundation" "-framework Security")
endif()

# Copy web assets and config to build directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/web
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/web
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/config.ini
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/config.ini
    COMMENT "Copying web assets and config..."
)

# Installation
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
install(DIRECTORY web/ DESTINATION share/${PROJECT_NAME}/web)
install(FILES config.ini DESTINATION etc/${PROJECT_NAME})
