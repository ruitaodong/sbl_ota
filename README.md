# Introduction 
This repo shows how to organize cmake files and the NXP code repo. I have eliminated most of the devices and boards that we do not need to keep size small. We can erase more devices if necessary.


# Getting Started
1. There are two directories - armgcc and src. All the build activities are performed under the armgcc directory. 
2. Add your source code to the proj_1170/src/<your name> directory.You might want to start with the azure_iot_mqtt directory and modify that.
3. Switch to the armgcc directory. Modify the CMakeLists.txt file to 
	a. Add the extra source files you added to the src directory
	b. Choose the build flag that you want - flexspi_nor_SDRAM or debug or whatever you like. They are listed in the flags.cmake file.
4. In the armgcc directory, use a command like cmake -S . -B build (-G Ninja). This will put all the build files in the build directory and keep your armgcc directory clean.
5. You elf file will be in the diretory that you chose as the build flag.

