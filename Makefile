obj-m += submitjob.o
submitjob-objs := sys_submitjob.o xcrypt.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xhw3 submitjob

user_net.o: user_net.c
	gcc -Wall -Werror -c user_net.c

xhw3: user_net.o xhw3.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi user_net.o -lssl -lpthread xhw3.c -o xhw3

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3
