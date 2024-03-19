#ifndef msggen_h
#define msggen_h
#include "fitsec.h"
#include "cstr.h"
#include "../uppertester/uppertester.h"

enum {
    MsgGenApp_DefaultApp = 1
};

typedef struct MsgGenApp MsgGenApp;
struct MsgGenApp {

    const char * appName;
    uint32_t flags;
    void (*process) (MsgGenApp * app, FitSec * e);
    int (*options)  (MsgGenApp * app, int argc, char* argv[]);
    size_t (*fill)  (MsgGenApp * app, FitSec * e, FSMessageInfo * m);
    void (*onEvent) (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);

    FSUT_Handler_fn  utHandler;
    void * utPtr;
};

void  MsgGenApp_Register(MsgGenApp * app);
void  MsgGenApp_Send(FitSec * e, MsgGenApp * a);

int FitSec_LoadTrustData(FitSec * e, FSTime32 curTime, const pchar_t * _path);


#endif
