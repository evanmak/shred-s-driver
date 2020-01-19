# Please make a softlink for path_to_kernel under current directory
# example:
# 	ln -s /home/zhichuang/stu/SHRED_SZC/linux path_to_kernel
PWD=$(shell pwd)
KERNEL_DIR=$(PWD)/path_to_kernel
ARCH=arm
CROSS_COMPILE=arm-linux-gnueabihf-
obj-m := dmm.o
all:
	make KERNEL=kernel7 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -C $(KERNEL_DIR) M=$(PWD) modules
clean:
		rm -rf *.o *.ko *.symvers *.mod.* *.order *.cmd
