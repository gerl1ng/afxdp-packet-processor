
BINARY = reqrouter
KERN_OBJ = $(BINARY)_kern.o

# Notice: the kbuilddir can be redefined on make cmdline
kbuilddir ?= /lib/modules/$(shell uname -r)/build/
KERNEL = $(kbuilddir)

# Includes to the current Kernel
LINUXINCLUDE := -I$(KERNEL)arch/x86/include
LINUXINCLUDE += -I$(KERNEL)arch/x86/include/generated/uapi
LINUXINCLUDE += -I$(KERNEL)arch/x86/include/generated
LINUXINCLUDE += -I$(KERNEL)include
LINUXINCLUDE += -I$(KERNEL)arch/x86/include/uapi
LINUXINCLUDE += -I$(KERNEL)include/uapi
LINUXINCLUDE += -I$(KERNEL)include/generated/uapi
LINUXINCLUDE += -include $(KERNEL)include/linux/kconfig.h
LINUXINCLUDE += -I$(KERNEL)tools/lib

NOSTDINC_FLAGS := -nostdinc -isystem $(shell gcc -print-file-name=include)

HOSTCFLAGS := -O2 -Wall #-H
HOSTCFLAGS += -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__
HOSTCFLAGS += -D__TARGET_ARCH_$(ARCH)
HOSTCFLAGS += -Werror
HOSTCFLAGS += -Wno-unused-value -Wno-pointer-sign
HOSTCFLAGS += -Wno-compare-distinct-pointer-types
HOSTCFLAGS += -Wno-gnu-variable-sized-type-not-at-end
HOSTCFLAGS += -Wno-tautological-compare
HOSTCFLAGS += -Wno-unknown-warning-option
HOSTCFLAGS += -Wno-address-of-packed-member

CFLAGS := -O2 -Wall -Werror
CFLAGS += -I$(KERNEL)usr/include
CFLAGS += -I$(KERNEL)tools/include
CFLAGS += -I$(KERNEL)tools/lib
CFLAGS += -I$(KERNEL)tools/perf/include

# Objects that xxx_user program is linked with:
OBJECT_BPF     = $(KERNEL)tools/lib/bpf/bpf.o
OBJECT_BTF     = $(KERNEL)tools/lib/bpf/btf.o
OBJECT_LIBBPF  = $(KERNEL)tools/lib/bpf/libbpf.o
OBJECT_BPFSTR  = $(KERNEL)tools/lib/bpf/str_error.o
OBJECT_NLATTR  = $(KERNEL)tools/lib/bpf/nlattr.o
OBJECTS = $(OBJECT_BPF) $(OBJECT_BTF) $(OBJECT_LIBBPF) $(OBJECT_BPFSTR) $(OBJECT_NLATTR)

all: $(KERN_OBJ) $(BINARY)

# BPF Kernel Object
$(KERN_OBJ): $(KERN_OBJ:%.o=%.c)
	clang $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(HOSTCFLAGS) \
		-S -emit-llvm -c $<
	llc -march=bpf -filetype=obj -o $@ $(KERN_OBJ:%.o=%.ll)

# Userspace program
$(BINARY): %: $(BINARY)_user.c ../common/functions.h $(OBJECTS) Makefile
	gcc -g $(CFLAGS) $(OBJECTS) -lelf -pthread -o reqrouter $<

# Catchall for the objects
%.o: %.c
	gcc $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -rf *.o *.ll $(BINARY)

.PHONY: run1t1q
run1t1q: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 1	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11 ./$(BINARY) -i ens4 -S

.PHONY: run2t1q
run2t1q: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 1	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11,9 ./$(BINARY) -i ens4 -S -t 2

.PHONY: run2t2q
run2t2q: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 2	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11,9 ./$(BINARY) -i ens4 -S -q 2

.PHONY: run4t2q
run4t2q: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 2	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11,9,7,5 ./$(BINARY) -i ens4 -S -q 2 -t 2

.PHONY: run4t4q
run4t4q: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 4	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11,9,7,5 ./$(BINARY) -i ens4 -S -q 4

.PHONY: run8t4q
run8t4q: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 4	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11,9,7,5,3,1,10,8 ./$(BINARY) -i ens4 -S -q 4 -t 2

.PHONY: run4poll
run4poll: $(BINARY) $(KERN_OBJ)
	sudo ethtool -L ens4 rx 4	# Set number of RX-Queues
	../set_queues.sh
	sudo taskset -c 11,9,7,5 ./$(BINARY) -i ens4 -S -q 4 -p

