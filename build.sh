gcc -std=gnu99 -Wall -g -o login_linux login_linux.c -lcrypt pwent.c && sudo chown root:root login_linux && sudo chmod 4755 login_linux && ./login_linux