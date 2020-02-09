/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sigh_3() {} /*  Catch Ctrl + \  */
void sigh_2() {} /*  Catch Ctrl + C  */
void sigh_kill() {} /*  Catch Ctrl + C  */


int main(int argc, char *argv[]) {

    mypwent *passwddata;

    char important1[LENGTH] = "**IMPORTANT 1**";

    char user[LENGTH];

    char important2[LENGTH] = "**IMPORTANT 2**";

    char *c_pass;
    char prompt[] = "password: ";
    char *user_pass;

    /* triggers some shortcuts */
    signal(2, sigh_2);
    signal(3, sigh_3);
    signal(SIGKILL, sigh_kill);


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
        user[strcspn(user, "\n")] = 0;


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

                printf("You're in !\n");
                printf("Number of failed attempts = %d\n", passwddata->pwfailed);

                /*  Reset failed attempts number */
                passwddata->pwfailed = 0;

                /*  Increment password age */
                passwddata->pwage++;
                if (passwddata->pwage > 10)
                    printf("For security reasons, you should change you password as soon as possible (password used %d times)\n",
                           passwddata->pwage);


                mysetpwent(user, passwddata);

                /*  UID checking */
                if (setuid(passwddata->uid) == -1) {
                    exit(0); /* setuid fails */
                }
                /*  start a shell with no arguments */
                printf("Launching shell with UID : %d\n", passwddata->uid);
                //printf("User new ID : %d\n", geteuid());
                char *pString[] = {"/bin/sh", "-c", "env", 0};
                execve("/bin/sh", &pString[0], (char *[]) {0});
                //execve("/bin/sh", &argv[0], (char *[]) {0});


            } else {
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
                if (passwddata->pwfailed > 5) {
                    printf("Too much login attempts, waiting %d seconds..\n", passwddata->pwfailed - 5);
                    sleep(passwddata->pwfailed);
                }
            }
        }
        printf("Login Incorrect \n");
    }
    return 0;
}
