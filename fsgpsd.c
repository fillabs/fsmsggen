#include <gps.h>
#include <math.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "cmem.h"
#include "clog.h"
#include "fitsec.h"
#include "fsgpsd.h"

static char _gpsd_default_port[] = "2947";

#define MAX_PORTS 16

static struct gps_data_t _gps[MAX_PORTS] = {};
static size_t _gps_cnt = 0;

static pthread_t _thr;
static pthread_mutex_t _mtx = PTHREAD_MUTEX_INITIALIZER;

int libgps_get_data(int ch, FSGpsData * data)
{
    int ret = -1;
    if(ch < _gps_cnt){
        pthread_mutex_lock(&_mtx);
        if(_gps[ch].gps_fd > 0){
            ret  =0 ;
            if(_gps[ch].status > 0) { // only when fix
                if(isfinite(_gps[ch].fix.latitude) && isfinite(_gps[ch].fix.longitude)){
                    data->position.latitude  = (int32_t)floor(_gps[ch].fix.latitude * 10000000.0);
                    data->position.longitude = (int32_t)floor(_gps[ch].fix.longitude * 10000000.0);
                }
                data->time = FSTime64from32(_gps[ch].fix.time.tv_sec) + (_gps[ch].fix.time.tv_sec/1000);
                if(isfinite(_gps[ch].fix.speed)){
                    data->speed = (long)floor(_gps[ch].fix.speed * 100.0); // in cm/s
                }else{
                    data->speed = 0;
                }
                if(isfinite(_gps[ch].fix.track)){
                    data->heading = (long)floor(_gps[ch].fix.track * 10.0); // in 0.1 degree
                }else{
                    data->heading = 0;
                }

                data->dx = _gps[ch].fix.epx;
                data->dy = _gps[ch].fix.epy;
                data->dh = _gps[ch].fix.eph;
                data->ds = _gps[ch].fix.eps;
                ret = 1;
            }
        }
    }
    pthread_mutex_unlock(&_mtx);
    return ret;
}

static void* gps_thread(char* p)
{
    fd_set rset;

    while(1){
        FD_ZERO(&rset);
//        FD_ZERO(&eset);
        int maxfd = 0;
        pthread_mutex_lock(&_mtx);
        for(int ch; ch < _gps_cnt; ch++){
            if(_gps[ch].gps_fd > 0){
                FD_SET(_gps[ch].gps_fd, &rset);
//                FD_SET(_gps[ch].gps_fd, &eset);
                if(_gps[ch].gps_fd > maxfd){
                    maxfd = _gps[ch].gps_fd;
                }
            }
        }
        pthread_mutex_unlock(&_mtx);
        struct timeval tv = {0, 100000};
        int n = select(maxfd + 1, &rset, NULL, NULL, &tv);
        pthread_testcancel ();
        for(int ch = 0; n && ch < _gps_cnt; ch++){
            if(FD_ISSET(_gps[ch].gps_fd, &rset)){
                pthread_mutex_lock(&_mtx);
                gps_read(&_gps[ch], NULL, 0);
                pthread_mutex_unlock(&_mtx);
                n--;
            }
        }
    }
    return NULL;
}

void libgps_stop( int ch)
{
    int stop = 1;
    pthread_mutex_lock(&_mtx);
    gps_close(&_gps[ch]);
    _gps[ch].gps_fd = 0;
    for(int ch = 0; ch < _gps_cnt; ch++){
        if(_gps[ch].gps_fd > 0){
            stop = 0;
            break;
        }
    }
    pthread_mutex_unlock(&_mtx);
    if(stop){
        void * rc;
        if(0 == pthread_cancel(_thr)){
            pthread_join(_thr, &rc);
        }
    }
}

int libgps_start(char * url )
{
    char * port = strrchr(url, ':');
    if(port){
        *(port++) = 0;
    }else{
        port = &_gpsd_default_port[0];
    }
    // select fd
    int rc = gps_open(url, port, &_gps[_gps_cnt]);
    if(rc == 0){
        if(0 == cfetch_and_inc(&_gps_cnt)){
            // 1st
            pthread_create(&_thr, NULL, (void*(*)(void*))gps_thread, NULL);
        }
    }else{
        mclog_error(GPSD, "%s:%s : %s\n", url, port, gps_errstr(rc));
    }
    return rc;
}
