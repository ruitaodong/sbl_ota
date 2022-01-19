include_guard(GLOBAL)
message("middleware_azure_rtos_azure_iot component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE 
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/nx_azure_iot.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/nx_azure_iot_hub_client.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/nx_azure_iot_json_reader.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/nx_azure_iot_json_writer.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/nx_azure_iot_provisioning_client.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/nx_azure_iot_security_module.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection_factory.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/collector_collection_internal.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors_info.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/core.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/logger.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/collectors/collector_network_activity.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/collectors/collector_system_information.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/utils/irand.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/utils/itime.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/utils/iuuid.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/utils/os_utils.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/collectors/collector_heartbeat.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/model/collector.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/model/security_message.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/heartbeat.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/network_activity.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/serializer.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/serializer_private.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/system_information.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/utils/event_loop_be.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/utils/notifier.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/utils/string_utils.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/src/model/objects/object_network_activity_ext.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_context.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_http_pipeline.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_http_policy.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_http_policy_logging.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_http_policy_retry.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_http_request.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_http_response.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_json_reader.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_json_token.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_json_writer.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_log.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_precondition.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/core/az_span.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_common.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_c2d.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_methods.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_sas.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_telemetry.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_hub_client_twin.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_provisioning_client.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/src/azure/iot/az_iot_provisioning_client_sas.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/extensions/custom_builder_allocator.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/extensions/custom_emitter.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/src/serializer/extensions/page_allocator.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/deps/flatcc/src/runtime/builder.c
${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/deps/flatcc/src/runtime/refmap.c)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot
    ${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure-sdk-for-c/sdk/inc
    ${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module
    ${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/inc
    ${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/inc
    ${CMAKE_CURRENT_LIST_DIR}/netxduo/addons/azure_iot/azure_iot_security_module/iot-security-module-core/deps/flatcc/include
)


