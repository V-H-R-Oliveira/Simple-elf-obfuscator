all:
	gcc -Wall -Werror -Wextra -O3 -s -o obfuscator main.c
	gcc -Wall -Werror -Wextra -O3 -s -o example example.c
	sh strip-all.sh
clean:
	rm obfuscator example