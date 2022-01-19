include_guard(GLOBAL)
message("dns_adu_addon component is included.")


target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/../dns_adu_addon/nxd_dns.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/../dns_adu_addon/
)


