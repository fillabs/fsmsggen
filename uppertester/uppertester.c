#include <csocket.h>
#include <cmem.h>
#include <cstr.h>
#include <cring.h>
#include <time.h>
#include <stdio.h>
#include "uppertester.h"

typedef struct FSUT_Handler {
    cring_t ring;
    FSUT_Handler_fn handler;
    void* ptr;
}FSUT_Handler;

struct FSUT
{
    csocket_t s;
    struct sockaddr_in local;
    struct sockaddr_in remote;
    cring_t handlers;
    unsigned char buf[FSUT_MAX_MSG_SIZE];
    cring_t out;
};

typedef struct FSUT_Msg {
    cring_t ring;
    size_t  size;
    FSUT_Message m;
}FSUT_Msg;

FSUT_Msg * FSUT_Msg_New(size_t l){
    FSUT_Msg * m = (FSUT_Msg *)malloc(l + sizeof(FSUT_Msg) - sizeof(FSUT_Message));
    cring_init(&m->ring);
    m->size = l;
    return m;
}

static uint16_t _unpack_uint16(const void * p){
    const uint8_t *s = p;
    uint16_t v = s[0];
    return (v<<8) + s[1];
}

static size_t _FSUT_CalcSize_guc (const FSUT_Message * m)
{
    uint16_t l = _unpack_uint16(&m->guc.payloadLength);
    return sizeof(struct FSUTMsg_GeoUnicast) + l;
}
static size_t _FSUT_CalcSize_gbc (const FSUT_Message * m)
{
    uint16_t l = _unpack_uint16(&m->gbc.payloadLength);
    return sizeof(struct FSUTMsg_GeoBroadcast) + l;
}
static size_t _FSUT_CalcSize_shb (const FSUT_Message * m)
{
    uint16_t l = _unpack_uint16(&m->shb.payloadLength);
    return sizeof(struct FSUTMsg_SHB) + l;
}
static size_t _FSUT_CalcSize_tsb (const FSUT_Message * m)
{
    uint16_t l = _unpack_uint16(&m->tsb.payloadLength);
    return sizeof(struct FSUTMsg_TSB) + l;
}
static size_t _FSUT_CalcSize_ind (const FSUT_Message * m)
{
    uint16_t l = _unpack_uint16(&m->indication.pduLength);
    return sizeof(struct FSUTMsg_Indication) + l;
}
static size_t _FSUT_CalcSize_PTActivation (const FSUT_Message * m)
{
    return sizeof(struct FSUTMsg_SetPtActivation) + m->setPtActivation.length;
}
static size_t _FSUT_CalcSize_DenmTrigger (const FSUT_Message * m)
{
    return sizeof(struct FSUTMsg_DenmTrigger) + m->denmTrigger.alacarteLength;
}
static size_t _FSUT_CalcSize_pkiTrustReq (const FSUT_Message * m)
{
    return sizeof(struct FSUTMsg_PkiTrustTrigger) + cstrlen(m->pkiTrust.path);
}
static struct {
    size_t size;
    size_t (*calc)(const FSUT_Message * m);
}_msizes [] = {
    [FS_UtInitialize]                              = {sizeof(struct FSUTMsg_Initialize)},
    [FS_UtInitializeResult]                        = {sizeof(struct FSUTMsg_Result)},
    [FS_UtChangePosition]                          = {sizeof(struct FSUTMsg_ChangePosition)},
    [FS_UtChangePositionResult]                    = {sizeof(struct FSUTMsg_Result)},
    [FS_UtChangePseudonym]                         = {sizeof(struct FSUTMsg_ChangePseudonym)},
    [FS_UtChangePseudonymResult]                   = {sizeof(struct FSUTMsg_Result)},
    [FS_UtCamTrigger]                              = {sizeof(struct FSUTMsg_Result)},
    [FS_UtCamTriggerResult]                        = {sizeof(struct FSUTMsg_Result)},
    [FS_UtCamEventInd]                             = {0, _FSUT_CalcSize_ind},
    [FS_UtCamTrigger_changeCurvature]              = {sizeof(struct FSUTMsg_ChangeCurvature)},
    [FS_UtCamTrigger_changeSpeed]                  = {sizeof(struct FSUTMsg_ChangeSpeed)},
    [FS_UtCamTrigger_setAccelerationControlStatus] = {sizeof(struct FSUTMsg_SetAccelerationControlStatus)},
    [FS_UtCamTrigger_setExteriorLightsStatus]      = {sizeof(struct FSUTMsg_SetExteriorLightsStatus)},
    [FS_UtCamTrigger_changeHeading]                = {sizeof(struct FSUTMsg_ChangeHeading)},
    [FS_UtCamTrigger_setDriveDirection]            = {sizeof(struct FSUTMsg_SetDriveDirection)},
    [FS_UtCamTrigger_changeYawRate]                = {sizeof(struct FSUTMsg_ChangeYawRate)},
    [FS_UtCamTrigger_setStationType]               = {sizeof(struct FSUTMsg_SetStationType)},
    [FS_UtCamTrigger_setVehicleRole]               = {sizeof(struct FSUTMsg_SetVehicleRole)},
    [FS_UtCamTrigger_setEmbarkationStatus]         = {sizeof(struct FSUTMsg_SetEmbarkationStatus)},
    [FS_UtCamTrigger_setPtActivation]              = {0, _FSUT_CalcSize_PTActivation},
    [FS_UtCamTrigger_setDangerousGoods]            = {sizeof(struct FSUTMsg_SetDangerousGoods)},
    [FS_UtCamTrigger_setLightBarSiren]             = {sizeof(struct FSUTMsg_SetLightBarSiren)},
    [FS_UtDenmTrigger]                             = {0, _FSUT_CalcSize_DenmTrigger},
    [FS_UtDenmTriggerResult]                       = {sizeof(struct FSUTMsg_DenmTriggerResult)},
    [FS_UtDenmUpdate]                              = {0, _FSUT_CalcSize_DenmTrigger},
    [FS_UtDenmUpdateResult]                        = {sizeof(struct FSUTMsg_DenmTriggerResult)},
    [FS_UtDenmTermination]                         = {sizeof(struct FSUTMsg_DenmTerminate)},
    [FS_UtDenmTerminationResult]                   = {sizeof(struct FSUTMsg_DenmTriggerResult)},
    [FS_UtDenmEventInd]                            = {0, _FSUT_CalcSize_ind},
    [FS_UtGnTriggerResult]                         = {sizeof(struct FSUTMsg_Result)},
    [FS_UtGnTrigger_geoUnicast]                    = {0, _FSUT_CalcSize_guc},
    [FS_UtGnTrigger_geoBroadcast]                  = {0, _FSUT_CalcSize_gbc},
    [FS_UtGnTrigger_geoAnycast]                    = {0, _FSUT_CalcSize_gbc},
    [FS_UtGnTrigger_shb]                           = {0, _FSUT_CalcSize_shb},
    [FS_UtGnTrigger_tsb]                           = {0, _FSUT_CalcSize_tsb},
    [FS_UtGnEventInd]                              = {0, _FSUT_CalcSize_ind},
    [FS_UtGenerateInnerEcRequest]                  = {1},
    [FS_UtGenerateInnerAtRequest]                  = {1},
    [FS_UtGenerateInnerEcResult]                   = {sizeof(struct FSUTMsg_Result )},
    [FS_UtGenerateInnerAtResult]                   = {sizeof(struct FSUTMsg_Result )},
    [FS_UtPkiTriggerInd]                           = {0, _FSUT_CalcSize_ind},
    [FS_UtPkiTriggerRcaCtlRequest]                 = {0, _FSUT_CalcSize_pkiTrustReq},
    [FS_UtPkiTriggerTlmCtlRequest]                 = {0, _FSUT_CalcSize_pkiTrustReq},
    [FS_UtPkiTriggerCrlRequest]                    = {0, _FSUT_CalcSize_pkiTrustReq},
    [FS_UtVamTrigger]                              = {sizeof(struct FSUTMsg_SetCamState)},
    [FS_UtVamLeader]                               = {sizeof(struct FSUTMsg_VamCluster)},
    [FS_UtVamJoin]                                 = {sizeof(struct FSUTMsg_VamCluster)}
};

static int _usr_to_sinaddr(const char * addr, struct sockaddr_in * a)
{
    const char * q = strchr(addr, ':');
    const char * c = addr;
    if(q){
        char * e;
        unsigned long n = strtoul(q+1, &e, 0);
        if(*e == 0 && n <= 0xFFFF){
            a->sin_port = cint16_hton((unsigned short)n);
        }
        if(addr == q){
            return 0;
        }
        
        c = cstrndup(addr, q - addr);
    }
    int rc = 0;
    if(0 > inet_pton(AF_INET, c, &a->sin_addr)){
        perror(c);
        a->sin_addr.s_addr = INADDR_ANY;
        rc = -1;
    }
    if(c != addr) free((void*)c);
    return rc;
}

FSUT* FSUT_New(const char* local_addr, const char* remote_addr)
{
    FSUT* ut = cnew0(FSUT);
    ut->local.sin_family = PF_INET;
    ut->local.sin_addr.s_addr = INADDR_ANY;
    ut->local.sin_port = cint16_hton(FSUT_DEFAULT_PORT);
    
    ut->remote.sin_family = PF_INET;
    ut->remote.sin_addr.s_addr = INADDR_ANY;
    ut->remote.sin_port = 0;

    if (local_addr) {
        _usr_to_sinaddr(local_addr, &ut->local);
    }
    if (remote_addr) {
        _usr_to_sinaddr(remote_addr, &ut->remote);
    }

    cring_init(&ut->handlers);
    cring_init(&ut->out);
    return ut;
}

void  FSUT_Free(FSUT* ut)
{
    if (ut) {
        FSUT_Stop(ut);
        cring_cleanup(&ut->handlers, free);
        cring_cleanup(&ut->out, free);
        free(ut);
    }
}

void  FSUT_RegisterHandler(FSUT* ut, FSUT_Handler_fn handler, void* ptr)
{
    FSUT_Handler* h = cnew(FSUT_Handler);
    cring_init(&h->ring);
    h->handler = handler;
    h->ptr = ptr;
    cring_enqueue(&ut->handlers, h);
}

int FSUT_Start(FSUT* ut)
{
#ifdef _MSC_VER
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
#endif
    csocket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s > 0) {
        int flags = 1;
        const char* fn = "setsockopt";
        if (0 <= setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&flags, sizeof(flags))) {
            fn = "bind";
            if (0 <= bind(s, (struct sockaddr*)&ut->local, sizeof(ut->local))) {
                ut->s = s;
                return 0;
            }
        }
        perror(fn);
        csocket_close(s);
    }
    return -1;
}

void  FSUT_Stop(FSUT* ut)
{
    if (ut->s) {
        csocket_t s = ut->s;
        ut->s = 0;
        csocket_close(s);
    }
}

static int _FSUT_Proceed(FSUT* ut, struct timeval * tv)
{
    if (!ut) return -1;
    int nfds = 1, len = 0;
    fd_set rs = { 0 }, es = { 0 };
    csocket_t s = ut->s;
    FD_SET(ut->s, &rs);
    FD_SET(ut->s, &es);
#ifndef _MSC_VER
    nfds = s + 1;
#endif
    int n = select(nfds, &rs, NULL, &es, tv);
    if (n < 0){
        perror("select");
        return -1;
    }
    if(ut->out.next != &ut->out){
        FSUT_Msg * m = (FSUT_Msg *)ut->out.next;
        cring_erase(&m->ring);
        sendto(ut->s, (const char*)(&m->m), m->size, 0, (const struct sockaddr*)&ut->remote, sizeof(struct sockaddr_in));
        free(m);
    }
    if (n > 0){
        if (FD_ISSET(s, &es)) {
            return -1;
        }
        if (FD_ISSET(s, &rs)) {
            socklen_t salen = sizeof(struct sockaddr_in);
            struct sockaddr_in remote = { 0 };
            len = recvfrom(ut->s, ut->buf, FSUT_MAX_MSG_SIZE, 0, (struct sockaddr*)&remote, &salen);
            if (0 > len) {
                return len;
            }

            int outlen = FSUT_onUTMessage(ut, (const char*)(ut->buf), len);
            if (outlen > 0) {
                sendto(ut->s, (const char*)(ut->buf), outlen, 0, (const struct sockaddr*)&remote, sizeof(struct sockaddr_in));
            }
            FSUT_Message* m = (FSUT_Message*)&ut->buf[0];
            if (m->code <= 1) { // utInitialize or Result
                ut->remote = remote;
            }
        }
    }
    return len;
}

int   FSUT_Run(FSUT* ut)
{
    if (ut && ut->s) {
        struct timeval tv = {
            0, 100000
        };
        do {
            int len = _FSUT_Proceed(ut, &tv);
            if(len < 0){
                if (! ut->s ) {
                    // stop;
                    break;
                }
                // error
                FSUT_Stop(ut);
                FSUT_Start(ut);
                continue;
            }
        } while (ut->s > 0);
    }
    return 0;
}

int   FSUT_Proceed(FSUT* ut, FSUT_Message * m, struct timeval* ptv)
{
    struct timeval tv = { 0,0 };
    if(m){
      FSUT_onUTMessage(ut, (const char*) m, 0);
    }
    if(ptv == NULL) ptv = &tv;
    return _FSUT_Proceed(ut, &tv);
}

int   FSUT_onUTMessage(FSUT* ut, const char* buf, size_t size)
{
    if (ut) {
        FSUT_Message* m = (FSUT_Message*)buf;
        FSUT_Handler* h = cring_first_cast(ut->handlers, FSUT_Handler);
        for (; &h->ring != &ut->handlers; h = cring_next_cast(h, FSUT_Handler)) {
            int s = (int)size;
            int rc = h->handler(ut, h->ptr, m, &s);
            if (rc > 0) {
                // we have to send this result
                return (size_t)s;
            }
        }
    }
    return 0;
}

int   FSUT_SendMessage(FSUT* ut, const FSUT_Message * msg, size_t size)
{
    if(ut->remote.sin_addr.s_addr != INADDR_ANY && ut->remote.sin_port){
        if(size == 0){
            if(msg->code >= (sizeof(_msizes)/sizeof(_msizes[0]))){
                return -1;
            }
            if(_msizes[msg->code].calc){
                size = _msizes[msg->code].calc(msg);
            }else{
                size = _msizes[msg->code].size;
            }
            if(size == 0){
                return -1;
            }
        }
        if(size == sendto(ut->s, (const char*)(msg), size, 0, (const struct sockaddr*)&ut->remote, sizeof(struct sockaddr_in))){
            return 0;
        }
    }
    return -1;
}

int FSUT_SendIndication(FSUT* ut, uint8_t code, const char* buf, size_t size)
{
    FSUT_Message * m;
    char _tmp[32];
    size_t len;
    if(ut) {
        switch(code){
        case FS_UtPkiTriggerInd:
            m = (FSUT_Message *)_tmp;
            m->pkiState.state = buf[0];
            len = sizeof(m->pkiState);
            break;
        default:
            m = (FSUT_Message *)struct_from_member(struct FSUTMsg_Indication, buf, pdu);
            m->indication.pduLength = cint16_hton((uint16_t)size);
            len = size + 3;
            break;
        }
        m->code = code; 
        sendto(ut->s, (const char*)(m), len, 0, (const struct sockaddr*)&ut->remote, sizeof(struct sockaddr_in));
        return 0;
    }
    return -1;
}

void FSUT_EnqueueIndication(FSUT* ut, uint8_t code, const char* buf, size_t size)
{
    if(ut) {
        FSUT_Msg * m; 
        switch(code){
        case FS_UtPkiTriggerInd:
            m = FSUT_Msg_New(sizeof(m->m.pkiState));
            m->m.pkiState.state = buf[0];
            m->size = sizeof(m->m.pkiState);
            break;
        default:
            m = FSUT_Msg_New(3+size);
            memcpy(m->m.indication.pdu, buf, size);
            m->m.indication.pduLength = cint16_hton((uint16_t)size);
            break;
        }
        m->m.code = code;
        cring_enqueue(&ut->out, &m->ring); 
    }
}
