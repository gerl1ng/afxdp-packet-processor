BINARY	= reqrouter
OBJ 	= $(BINARY).o
CFLAGS 	= -Wall -g -Werror

$(BINARY): $(OBJ) ../common/functions.h
	gcc $(CFLAGS) -pthread -o $@ $<

%.o: %.c
	gcc $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(BINARY) $(OBJ)

.PHONY: run_unoptimized
run_unoptimized: $(BINARY)
	./$(BINARY) -u

.PHONY: run1t1q
run1t1q: $(BINARY)
	sudo ethtool -L ens4 rx 1       # Set number of RX-Queues
	../set_queues.sh
	taskset -c 11 ./$(BINARY) -t 1

.PHONY: run2t1q
run2t1q: $(BINARY)
	sudo ethtool -L ens4 rx 2       # Set number of RX-Queues
	../set_queues.sh
	taskset -c 11,9 ./$(BINARY) -t 2

.PHONY: run2t2q
run2t2q: $(BINARY)
	sudo ethtool -L ens4 rx 2       # Set number of RX-Queues
	../set_queues.sh
	taskset -c 11,9 ./$(BINARY) -t 2

.PHONY: run4t2q
run4t2q: $(BINARY)
	sudo ethtool -L ens4 rx 2       # Set number of RX-Queues
	../set_queues.sh
	taskset -c 11,9,7,5 ./$(BINARY) -t 4

.PHONY: run4t4q
run4t4q: $(BINARY)
	sudo ethtool -L ens4 rx 4       # Set number of RX-Queues
	../set_queues.sh
	taskset -c 11,9,7,5 ./$(BINARY) -t 4

.PHONY: run8t4q
run8t4q: $(BINARY)
	sudo ethtool -L ens4 rx 4       # Set number of RX-Queues
	../set_queues.sh
	taskset -c 11,9,7,5,3,1,10,8 ./$(BINARY) -t 8

