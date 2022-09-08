#ifndef msggen_h
#define msggen_h
#include "fitsec.h"
#include "../uppertester/uppertester.h"

enum {
    MsgGenApp_DefaultApp = 1
};

typedef struct MsgGenApp MsgGenApp;
struct MsgGenApp {

    const char * appName;
    uint32_t flags;
    int (*options) (MsgGenApp * app, int argc, char* argv[]);
    size_t (*fill) (MsgGenApp * app, FitSec * e, FSMessageInfo * m);
    FSUT_Handler_fn  utHandler;
};

void  MsgGenApp_Register(MsgGenApp * app);

#endif
