#ifndef fsgpsd_h
#define fsgpsd_h
#include "fitsec_types.h"

typedef struct FSGpsData {
    FSTime64     time;
    FS3DLocation position;
    int32_t      heading;
    int32_t      speed;
    double       dx, dy, dh, ds;
}FSGpsData;

int  libgps_start  (char * url );
void libgps_stop   (int ch);
int  libgps_get_data(int ch, FSGpsData * data);


#endif
