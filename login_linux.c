/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"
#include <unistd.h>

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler(int sig_num) {
    printf("%d",sig_num);
    switch(sig_num){
        case 2:
            signal(SIGINT, sighandler);
            printf("Cannot execute Ctrl+C\n");
            break;
        case 20:
            signal(SIGTSTP, sighandler);
            printf("Cannot execute Ctrl+Z\n");
            break;

    }

}

int main(int argc, char *argv[]) {

    mypwent *passwddata;

    char important1[LENGTH] = "**IMPORTANT 1**";

    char user[LENGTH];

    char important2[LENGTH] = "**IMPORTANT 2**";

    char *c_pass;
    char prompt[] = "password: ";
    char *user_pass;


    signal(SIGINT, sighandler);
    signal(SIGTSTP, sighandler);


    while (TRUE) {
        /* check what important variable contains - do not remove, part of buffer overflow test */
        printf("Value of variable 'important1' before input of login name: %s\n",
               important1);
        printf("Value of variable 'important2' before input of login name: %s\n",
               important2);

        printf("login: ");
        fflush(NULL); /* Flush all  output buffers */
        __fpurge(stdin); /* Purge any data in stdin buffer */

        if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
            exit(0); /*  overflow attacks.  */
        user[strlen(user) - 1] = '\0';



        /* check to see if important variable is intact after input of login name - do not remove */
        printf("Value of variable 'important 1' after input of login name: %*.*s\n",
               LENGTH - 1, LENGTH - 1, important1);
        printf("Value of variable 'important 2' after input of login name: %*.*s\n",
               LENGTH - 1, LENGTH - 1, important2);

        user_pass = getpass(prompt);
        passwddata = mygetpwnam(user);

        if (passwddata != NULL) {
            /* password encryption using salt */
            c_pass = crypt(user_pass, passwddata->passwd_salt);

            if (!strcmp(c_pass, passwddata->passwd)) {

                printf("Number of failed attempts = %d\n", passwddata->pwfailed);
                printf(" You're in !\n");
                passwddata->pwfailed = 0;
                passwddata->pwage++;
                if (passwddata->pwage > 10)
                    printf("For security reasons, you should change you password as soon as possible (passwd_age is %d)\n",
                           passwddata->pwage);


                mysetpwent(user, passwddata);

                /*  UID checking */
                setuid(passwddata->uid);
                /*  start a shell with no arguments */
                execve("/bin/sh", 0, 0);


            } else {
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
                if (passwddata->pwfailed > 10) {
                    printf("Too much login attempts, waiting %d seconds..\n", passwddata->pwfailed - 10);
                    sleep(passwddata->pwfailed);
                }
            }
        }
        printf("Login Incorrect \n");
    }
    return 0;
}
