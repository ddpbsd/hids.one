/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "maild.h"
#include "mail_list.h"

#include "os_net/os_net.h"
#include "os_dns.h"

#ifndef ARGV0
#define ARGV0 "ossec-maild"
#endif

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

static int errcnt = 0;

/* Prototypes */
static void help_maild(void) __attribute__((noreturn));


/* Print help statement */
static void help_maild()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", MAILUSER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = MAILUSER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Mail Structure */
    MailConfig mail;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_maild();
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'u':
                if (!optarg) {
                    ErrorExit("%s: -u needs an argument", ARGV0);
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -D needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument", ARGV0);
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_maild();
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }

    /* Read configuration */
    if (MailConf(test_config, cfg, &mail) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Read internal options */
    mail.strict_checking = getDefine_Int("maild",
                                         "strict_checking",
                                         0, 1);

    /* Get groupping */
    mail.groupping = getDefine_Int("maild",
                                   "groupping",
                                   0, 1);

    /* Get subject type */
    mail.subject_full = getDefine_Int("maild",
                                      "full_subject",
                                      0, 1);

#ifdef LIBGEOIP_ENABLED
    /* Get GeoIP */
    mail.geoip = getDefine_Int("maild",
                               "geoip",
                               0, 1);
#endif

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

#if __OpenBSD__
    setproctitle("[main]");     
#endif

    /* Prepare environment for os_dns */
    struct imsgbuf osdns_ibuf;
    int imsg_fds[2];
    if ((socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds)) == -1) {
        ErrorExit("%s: ERROR: Could not create socket pair.", ARGV0);
    }
    if (setnonblock(imsg_fds[0]) < 0) {
        ErrorExit("%s: ERROR: Cannot set imsg_fds[0] to nonblock", ARGV0);
    }
    if (setnonblock(imsg_fds[1]) < 0) {
        ErrorExit("%s: ERROR: Cannot set imsg_fds[1] to nonblock", ARGV0);
    }

    /* Fork off the os_dns process */
    pid_t dnspid = fork();
    switch(dnspid) {
        case -1:
            ErrorExit("%s: ERROR: Cannot fork() os_dns process", ARGV0);
        case 0:
            close(imsg_fds[0]);
            imsg_init(&osdns_ibuf, imsg_fds[1]);
            exit(maild_osdns(&osdns_ibuf, ARGV0, mail));
    }

    /* Setup imsg for the rest of maild */
    close(imsg_fds[1]);
    imsg_init(&mail.ibuf, imsg_fds[0]);

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    if (mail.smtpserver[0] != '/') {
        /* chroot */
        if (Privsep_Chroot(dir) < 0) {
            ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
        }
        nowChroot();
        debug1(CHROOT_MSG, ARGV0, dir);
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    debug1(PRIVSEP_MSG, ARGV0, user);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    /* The real daemon now */
    OS_Run2(&mail);
}

