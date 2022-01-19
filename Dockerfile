FROM	ubuntu:bionic

RUN	apt-get update && apt-get install -y cmake gcc-arm-none-eabi

ADD	mcuxsdk /opt/nxp/mcuxsdk
ADD	proj_1170/sbl_ota sbl_ota
WORKDIR sbl_ota/cm7/armgcc

RUN	rm -r -f flexspi_nor_debug && mkdir -p flexspi_nor_debug && cd flexspi_nor_debug && cmake .. && make -k -j8 VERBOSE=1
