#include <csocket.h>
#include <cmem.h>
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
    struct sockaddr_in from;
    cring_t handlers;
    unsigned char      buf[FSUT_MAX_MSG_SIZE];
};

FSUT* FSUT_New(const char* bind_host, int bind_port)
{
    FSUT* ut = cnew0(FSUT);
    ut->local.sin_family = PF_INET;
    ut->local.sin_addr.s_addr = INADDR_ANY;
    if (bind_host) {
        if (0 > inet_pton(AF_INET, bind_host, &ut->local.sin_addr)) {
            perror(bind_host);
            ut->local.sin_addr.s_addr = INADDR_ANY;
        }
    }
    ut->local.sin_port = cint16_hton(bind_port);

    cring_init(&ut->handlers);
    return ut;
}

void  FSUT_Free(FSUT* ut)
{
    if (ut) {
        FSUT_Stop(ut);
        cring_cleanup(&ut->handlers, free);
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
    if (n > 0){
        if (FD_ISSET(s, &es)) {
            return -1;
        }
        if (FD_ISSET(s, &rs)) {
            socklen_t salen = sizeof(struct sockaddr_in);
            struct sockaddr_in from = { 0 };
            len = recvfrom(ut->s, ut->buf, FSUT_MAX_MSG_SIZE, 0, (struct sockaddr*)&from, &salen);
            if (0 > len) {
                return len;
            }

            int outlen = FSUT_onUTMessage(ut, (const char*)(ut->buf), len);
            if (outlen > 0) {
                sendto(ut->s, (const char*)(ut->buf), outlen, 0, (const struct sockaddr*)&from, sizeof(struct sockaddr_in));
            }
            FSUT_Message* m = (FSUT_Message*)&ut->buf[0];
            if (m->code <= 1) { // utInitialize or Result
                ut->from = from;
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

int   FSUT_Proceed(FSUT* ut)
{
    struct timeval tv = { 0,0 };
    return _FSUT_Proceed(ut, &tv);
}

unsigned long long unix2itstime64(time_t t);

int   FSUT_onUTMessage(FSUT* ut, const char* buf, size_t size)
{
    if (ut) {
        FSUT_Message* m = (FSUT_Message*)&ut->buf[0];
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

int   FSUT_SendIndication(FSUT* ut, uint8_t code, const char* buf, size_t size)
{
    if(ut) {
        struct FSUTMsg_Indication* m = struct_from_member(struct FSUTMsg_Indication, buf, pdu);
        m->code = FS_UtGnEventInd;
        m->pduLength = cint16_hton((uint16_t)size);
        sendto(ut->s, (const char*)(m), (int)(size + 3), 0, (const struct sockaddr*)&ut->from, sizeof(struct sockaddr_in));
        return 0;
    }
    return -1;
}

