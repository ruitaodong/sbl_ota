# CROSS COMPILER SETTING
SET(CMAKE_SYSTEM_NAME Generic)
CMAKE_MINIMUM_REQUIRED (VERSION 3.10.0)


# NXP repo downloaded location

set(ENV{ARMGCC_DIR} /usr)

SET(NXP_DOWNLOAD_HOME /opt/nxp/mcuxsdk)
include(${NXP_DOWNLOAD_HOME}/core/tools/cmake_toolchain_files/armgcc.cmake)
message(STATUS "COMPILER : ${CMAKE_C_COMPILER}" )

# THE VERSION NUMBER
SET (Tutorial_VERSION_MAJOR 1)
SET (Tutorial_VERSION_MINOR 0)

# ENABLE ASM
ENABLE_LANGUAGE(ASM)

SET(CMAKE_STATIC_LIBRARY_PREFIX)
SET(CMAKE_STATIC_LIBRARY_SUFFIX)

SET(CMAKE_EXECUTABLE_LIBRARY_PREFIX)
SET(CMAKE_EXECUTABLE_LIBRARY_SUFFIX)

# CURRENT DIRECTORY
SET(ProjDirPath ${CMAKE_CURRENT_SOURCE_DIR})

# set build type
SET(CMAKE_BUILD_TYPE flexspi_nor_debug)
#SET(CMAKE_BUILD_TYPE flexspi_nor_release)
#SET(CMAKE_BUILD_TYPE debug)

SET(EXECUTABLE_OUTPUT_PATH ${ProjDirPath}/${CMAKE_BUILD_TYPE})
SET(LIBRARY_OUTPUT_PATH ${ProjDirPath}/${CMAKE_BUILD_TYPE})

project(azure_iot_adu)

set(MCUX_SDK_PROJECT_NAME sbl_ota.elf)

SET(CMAKE_STATIC_LIBRARY_PREFIX "lib")

SET(CMAKE_STATIC_LIBRARY_SUFFIX ".a")

SET(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

SET(THREADX_ARCH "cortex_m7")

SET(THREADX_TOOLCHAIN "gnu")

SET(NX_USER_FILE ${ProjDirPath}/../src/nx_user.h)

SET(FX_USER_FILE ${ProjDirPath}/../src/fx_user.h)

SET(TX_USER_FILE ${ProjDirPath}/../src/tx_user.h)

include(${ProjDirPath}/flags.cmake)

include(${ProjDirPath}/config.cmake)

add_executable(${MCUX_SDK_PROJECT_NAME} 
"${ProjDirPath}/../src/pin_mux.c"
"${ProjDirPath}/../src/get_seed.c"
"${ProjDirPath}/../src/nx_driver_imxrt_irq.c"
"${ProjDirPath}/../src/nx_driver_imxrt.c"
"${ProjDirPath}/../src/board.c"
"${ProjDirPath}/../src/board_setup.c"
"${ProjDirPath}/../src/clock_config.c"
"${ProjDirPath}/../src/dcd.c"
"${ProjDirPath}/../src/main.c"
"${ProjDirPath}/../src/nx_azure_iot_ciphersuites.c"
"${ProjDirPath}/../src/nx_azure_iot_cert.c"
"${ProjDirPath}/../src/flexspi_nor_flash_ops.c"
"${ProjDirPath}/../src/flexspi_nor_edma_transfer.c"
"${ProjDirPath}/../src/sbl_ota_flag.c"
)

include(${ProjDirPath}/azure_iot_adu_addon.cmake)

include(${ProjDirPath}/dns_adu_addon.cmake)

# IOT Hub connection definitions
#target_compile_definitions( ${MCUX_SDK_PROJECT_NAME} PRIVATE
#DEVICE_ID=""
#HOST_NAME=""
#DEVICE_SAS=""
#)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${ProjDirPath}/../src
    ${ProjDirPath}/../tflm-model
    ${NXP_DOWNLOAD_HOME}/core/devices/MIMXRT1176
)

set(CMAKE_MODULE_PATH
    ${NXP_DOWNLOAD_HOME}/core
    ${NXP_DOWNLOAD_HOME}/rtos/azure-rtos_1170
    ${NXP_DOWNLOAD_HOME}/core/components/phy/mdio/enet
    ${NXP_DOWNLOAD_HOME}/core/components/phy/device/phyksz8081
    ${NXP_DOWNLOAD_HOME}/core/components/phy/device/phyrtl8211f
    ${NXP_DOWNLOAD_HOME}/core/devices/MIMXRT1176/drivers
    ${NXP_DOWNLOAD_HOME}/core/components/lists
    ${NXP_DOWNLOAD_HOME}/core/components/uart
    ${NXP_DOWNLOAD_HOME}/core/components/serial_manager
    ${NXP_DOWNLOAD_HOME}/core/drivers/caam
    ${NXP_DOWNLOAD_HOME}/core/drivers/edma
    ${NXP_DOWNLOAD_HOME}/core/drivers/dmamux
    ${NXP_DOWNLOAD_HOME}/core/drivers/flexspi
    ${NXP_DOWNLOAD_HOME}/core/devices/MIMXRT1176
    ${NXP_DOWNLOAD_HOME}/core/devices/MIMXRT1176/drivers/cm7
    ${NXP_DOWNLOAD_HOME}/core/devices/MIMXRT1176/xip
    ${NXP_DOWNLOAD_HOME}/core/devices/MIMXRT1176/utilities
    ${NXP_DOWNLOAD_HOME}/core/components/phy
    ${NXP_DOWNLOAD_HOME}/core/CMSIS/Core/Include
)

include(all_devices)

# include modules
include(middleware_azure_rtos_nxd_MIMXRT1176_cm7)
#include(middleware_azure_rtos_azure_iot_MIMXRT1176_cm7)

include(driver_mdio-enet)

include(driver_phy-device-ksz8081)

include(driver_phy-device-rtl8211f)

include(driver_caam)

include(driver_edma)

include(driver_dmamux)

include(driver_flexspi_edma)

include(component_lists)

include(component_lpuart_adapter)

include(component_serial_manager)

include(driver_common)

include(component_serial_manager_uart)

include(driver_lpuart)

include(device_CMSIS)

include(device_startup_MIMXRT1176_cm7)

include(driver_cache_armv7_m7)


include(driver_clock)

include(driver_dcdc_soc)

include(driver_igpio)

include(driver_iomuxc)

include(driver_lpi2c)

include(driver_pmu_1)

include(driver_xip_board_evkmimxrt1170)

include(driver_xip_device)

include(utility_assert)

include(utility_debug_console)

include(middleware_azure_rtos_nxd_template_MIMXRT1176_cm7)

include(middleware_azure_rtos_fx_MIMXRT1176_cm7)

include(middleware_azure_rtos_fx_template_MIMXRT1176_cm7)

include(middleware_azure_rtos_tx_MIMXRT1176_cm7)

include(middleware_azure_rtos_tx_template_MIMXRT1176_cm7)

include(driver_mdio-common)

include(driver_anatop_ai)

include(CMSIS_Include_core_cm)

include(driver_enet)

include(driver_memory)

include(driver_phy-common)

include(utilities_misc_utilities)

include(device_system_MIMXRT1176_cm7)

add_subdirectory(${NXP_DOWNLOAD_HOME}/rtos/azure-rtos_1170/netxduo ./CMakeFiles/libnetxduo)

add_subdirectory(${NXP_DOWNLOAD_HOME}/rtos/azure-rtos_1170/filex ./CMakeFiles/libfilex)

add_subdirectory(${NXP_DOWNLOAD_HOME}/rtos/azure-rtos_1170/threadx ./CMakeFiles/libthreadx)

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE -Wl,--start-group)

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE m)

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE c)

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE gcc)

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE nosys)

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE "azrtos::netxduo")

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE "azrtos::filex")

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE "azrtos::threadx")

target_link_libraries(${MCUX_SDK_PROJECT_NAME} PRIVATE -Wl,--end-group)

target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PRIVATE  SOC_REMAP_ENABLE=1)
