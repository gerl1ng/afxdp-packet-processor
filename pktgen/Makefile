BINARY	= pktgen
OBJ 	= $(BINARY).o
CFLAGS 	= -Wall -g -Werror

$(BINARY): $(OBJ)
	gcc $(CFLAGS) -pthread -o $@ $<

%.o: %.c
	gcc $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(BINARY) $(OBJ)

