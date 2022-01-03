build:
	gcc -g -Wall -Werror -Wextra -fPIC -c so_stdio.c
	gcc -shared so_stdio.o -o libso_stdio.so

clean:
	rm -rf so_stdio.o libso_stdio.so