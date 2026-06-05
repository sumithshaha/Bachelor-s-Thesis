cmake_minimum_required(VERSION 3.21.1)
project(ChatE2EE VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Qt 6.11 is the version used during development. The components used are:
#   Quick / QuickControls2 -> the QML UI
#   WebSockets             -> the wss:// transport to the server
#   Sql                    -> local SQLite message history
find_package(Qt6 6.5 REQUIRED COMPONENTS Quick QuickControls2 WebSockets Sql)

qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(appChatE2EE
    src/main.cpp
    src/chatclient.cpp
    src/chatclient.h
    src/messagemodel.cpp
    src/messagemodel.h
    src/usermodel.cpp
    src/usermodel.h
    src/cryptobox.cpp
    src/cryptobox.h
    src/filecrypto.cpp
    src/filecrypto.h
    src/historystore.cpp
    src/historystore.h
)

# Make headers in src/ visible as <chatclient.h>, <cryptobox.h>, etc., so
# Qt's auto-generated appchate2ee_qmltyperegistrations.cpp can resolve its
# __has_include(<chatclient.h>) guard and pick up the QML_ELEMENT class.
target_include_directories(appChatE2EE PRIVATE src)

# ---- libsodium ---------------------------------------------------------------
# On Windows we use the pre-built MinGW tarball extracted to C:/libsodium.
# On Linux/macOS we let CMake's find_library locate the system libsodium
# (apt install libsodium-dev / brew install libsodium / etc.).
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(NOT DEFINED SODIUM_ROOT)
        set(SODIUM_ROOT "C:/libsodium/libsodium-win64" CACHE PATH "libsodium prebuilt root")
    endif()
    if(NOT EXISTS "${SODIUM_ROOT}/include/sodium.h")
        message(FATAL_ERROR
            "libsodium not found at ${SODIUM_ROOT}. "
            "Extract libsodium-1.0.20-stable-mingw.tar.gz to C:/libsodium.")
    endif()
    target_include_directories(appChatE2EE PRIVATE "${SODIUM_ROOT}/include")
    target_link_libraries     (appChatE2EE PRIVATE "${SODIUM_ROOT}/lib/libsodium.dll.a")
    target_compile_definitions(appChatE2EE PRIVATE HAVE_SODIUM)
    add_custom_command(TARGET appChatE2EE POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SODIUM_ROOT}/bin/libsodium-26.dll"
            "$<TARGET_FILE_DIR:appChatE2EE>/libsodium-26.dll"
        COMMENT "Copying libsodium-26.dll next to appChatE2EE.exe")
else()
    # Linux / macOS path: pick up the system-installed libsodium.
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    if(SODIUM_LIBRARY)
        target_link_libraries(appChatE2EE PRIVATE ${SODIUM_LIBRARY})
        target_compile_definitions(appChatE2EE PRIVATE HAVE_SODIUM)
    endif()
endif()

qt_add_qml_module(appChatE2EE
    URI ChatE2EE
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/LoginPage.qml
        qml/ChatPage.qml
        qml/MessageDelegate.qml
        qml/UserListPanel.qml
)

target_link_libraries(appChatE2EE PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::WebSockets
    Qt6::Sql
)

# ---- Android-specific configuration --------------------------------------
if(ANDROID)
    set_property(TARGET appChatE2EE PROPERTY
        QT_ANDROID_PACKAGE_SOURCE_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/android")

    # --- Native libsodium, cross-compiled per ABI (real crypto on Android) -
    # The desktop build links a prebuilt libsodium DLL. Android has no such
    # prebuilt, so libsodium was cross-compiled from source with the NDK into
    # a static archive per ABI (see build_android.sh). Linking it here and
    # defining HAVE_SODIUM=1 makes the SAME real CryptoBox/FileCrypto code the
    # desktop uses compile on Android, instead of the no-op stubs. Without
    # this, the client registers an empty public key and the server rejects it
    # ("pubKey must be 32, got 0"). The archive is selected by ABI, so a
    # multi-ABI build picks arm64-v8a for phones and x86_64 for the emulator.
    set(SODIUM_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsodium")
    set(SODIUM_A "${SODIUM_ROOT}/${CMAKE_ANDROID_ARCH_ABI}/libsodium.a")
    if(EXISTS "${SODIUM_A}")
        add_library(sodium_static STATIC IMPORTED)
        set_target_properties(sodium_static PROPERTIES
            IMPORTED_LOCATION "${SODIUM_A}")
        target_include_directories(appChatE2EE PRIVATE
            "${SODIUM_ROOT}/include")
        target_link_libraries(appChatE2EE PRIVATE sodium_static)
        target_compile_definitions(appChatE2EE PRIVATE HAVE_SODIUM=1)
        message(STATUS "Android libsodium: linking ${SODIUM_A}")
    else()
        message(WARNING
            "Android libsodium .a not found for ABI ${CMAKE_ANDROID_ARCH_ABI} "
            "at ${SODIUM_A} - crypto will be STUBBED. Run build_android.sh and "
            "copy the archives into third_party/libsodium/<abi>/.")
    endif()

    # Bundle OpenSSL so Qt's network stack has a working TLS backend on
    # Android. Without this, wss:// connections fail at runtime with
    # "No functional TLS backend was found" - Qt does not ship OpenSSL for
    # Android, so the per-ABI libssl_3.so / libcrypto_3.so installed by Qt
    # Creator's Set Up SDK must be added to the deployment. The helper script
    # defines add_android_openssl_libraries(); for a Debug build it selects
    # the no-asm/ variant automatically. If the include path cannot be found,
    # replace $ENV{LOCALAPPDATA} below with the absolute path, e.g.
    # "C:/Users/Sumith/AppData/Local/Android/Sdk/android_openssl/android_openssl.cmake".
    include("$ENV{LOCALAPPDATA}/Android/Sdk/android_openssl/android_openssl.cmake"
            OPTIONAL RESULT_VARIABLE ANDROID_OPENSSL_INCLUDED)
    if(ANDROID_OPENSSL_INCLUDED)
        add_android_openssl_libraries(appChatE2EE)
    else()
        message(WARNING
            "android_openssl.cmake not found - TLS (wss://) will not work on "
            "Android. Check the path or re-run Set Up SDK in Qt Creator.")
    endif()

    # The only permission this app needs is network access.
    #
    # qt_add_android_permission() was introduced in Qt 6.8.1. On that version
    # or newer we declare the permission here; on older Qt the function does
    # not exist, so the permission is instead taken from the INTERNET line in
    # android/AndroidManifest.xml. Guarding the call this way means the project
    # configures cleanly on any Qt 6 version rather than failing with an
    # "unknown command" error on 6.5-6.7.
    if(COMMAND qt_add_android_permission)
        qt_add_android_permission(appChatE2EE
            NAME android.permission.INTERNET)
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS appChatE2EE
    BUNDLE  DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)