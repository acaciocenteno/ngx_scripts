CFLAGS=-std=gnu99 -Wall -Wextra -g
DEBUG=1
OBJ1=ngx_view_cache
OBJ2=ngx_update_cache

ifeq ($(DEBUG), 1)
	CFLAGS+=-O0
else
	CFLAGS+=-O3
endif

all: 
	gcc $(CFLAGS) -o $(OBJ1) $(OBJ1).c 
	gcc $(CFLAGS) -o $(OBJ2) $(OBJ2).c 

clean:
	rm -f $(OBJ1) $(OBJ2)

