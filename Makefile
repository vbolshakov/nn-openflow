ccflags-y := -O0 -std=gnu99 -Wno-declaration-after-statement

obj-m += nn-openflow.o
nn-openflow-objs += openflow.o openflow13.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

