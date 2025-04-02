#include <stdio.h>
#include <unistd.h>
#include "../uppertester.h"
#include "copts.h"
#include "cstr.h"

static const char * _o_local_addr = "0.0.0.0:0";
static const char * _o_ut_addr = "127.0.0.1:12345";
static int _o_cont = 0;

static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,           "Print this help page"},
    { "c",  NULL,       COPT_BOOL,     &_o_cont,       "Execute command line params and keep reading indications" },
    { "C",  "config",   COPT_CFGFILE,  NULL,           "Config file"         },
    { "l",  "bind",     COPT_STR,      &_o_local_addr, "Local bind address" },
    { "u",  "iut",      COPT_STR,      &_o_ut_addr,    "IUT Upper tester address" },
    { NULL, NULL, COPT_END, NULL, NULL }
};

int main (int argc, char ** argv) {
    int rc = coptions(argc, argv, COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP | COPT_NOHELP_MSG, options);
    if (COPT_ERC(rc)) {
        coptions_help(stdout, argv[0], 0, options,  "ITS Uppertester command utility");
        if (rc== COPT_EHELP) {
            printf("%s", FSUT_CommandHelp(NULL));
        }
        return 1;
    }

    FSUT * ut = FSUT_New(_o_local_addr, _o_ut_addr);
    if(ut == NULL){
        perror(_o_local_addr);
        return 1;
    }
    
    FSUT_Start(ut);

    argc = rc;
    int argi = 1;
    unsigned long n_pause = 0;
    for(;;){
        struct timeval tv = {0, 100000};
        if(argi >= argc){
            if(_o_cont == 0) break;
        }else{
            if(n_pause > 0){
                n_pause --;
            }else {
                if(cstrequal(argv[argi], "pause")){
                    char * e = NULL;
                    argi++;
                    if(argi==argc){
                        fprintf(stderr, "Command error: pause <msec>\n");
                        return 1;
                    }
                    n_pause = strtoul(argv[argi], &e, 10);
                    if(*e != 0 || n_pause == 0 || n_pause > 60000){ // more than 1 minute
                        fprintf(stderr, "Command error: pause <msec>\n");
                        return 1;
                    }
                    n_pause = (n_pause + 50) / 100; // tick is 100msec
                    argi++;
                }else {
                    FSUT_Message * umsg = NULL;
                    rc = FSUT_CommandMessage(&umsg, argc - argi, argv + argi);
                    if(rc <= 0){
                        if(rc < 0) rc = 255+rc;
                        fprintf(stderr, "Command error: %s\n", argv[rc+1]);
                        return 1;
                    }else if(rc > 0){
                        FSUT_SendMessage(ut, umsg, 0);
                        argi += rc;
                        free(umsg);
                    }
                }
            }
        }
       
        FSUT_Proceed(ut, NULL, &tv);
    }
    FSUT_Free(ut);
    return 0;
}
