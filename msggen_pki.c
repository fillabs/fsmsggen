#include "msggen.h"
#include "cmem.h"
#include "copts.h"
#include "cstr.h"

#include <curl/curl.h>

#include "fitsec_pki.h"

static int _options (MsgGenApp* app, int argc, char* argv[]);
static size_t _fill_none   (MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{return 0;}
static size_t _fill_auth   (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static size_t _fill_enr    (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static int  pki_ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);
static void pki_process_ea (MsgGenApp * app, FitSec * e);
static void pki_process_aa (MsgGenApp * app, FitSec * e);
static void pki_process_none (MsgGenApp * app, FitSec * e) {
    pki_process_ea (app, e);
    pki_process_aa (app, e);
}
static void pki_onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);

static FitSecPki * _pki = NULL;

static MsgGenApp _app = {
    "pki", MsgGenApp_DefaultApp, pki_process_none, _options, _fill_none, pki_onEvent, pki_ut_handler
};
static MsgGenApp _enr = {
    "enr", MsgGenApp_DefaultApp, pki_process_ea, _options, _fill_enr
};
static MsgGenApp _auth = {
    "auth", MsgGenApp_DefaultApp, pki_process_aa, _options, _fill_auth
};

__INITIALIZER__(initializer_pki) {
     MsgGenApp_Register(&_app);
}

static uint8_t station_id [] = {
    0xb1, 0xb8, 0xc6, 0xe0, 0xb7, 0x5d, 0xd6, 0xf6,
    0x76, 0xd5, 0x77, 0x43, 0x6b, 0xb5, 0x41, 0xde
};

static uint8_t priv_key [32] = {
    0x32, 0xB0, 0xBA, 0xC1, 0x9C, 0x38, 0xE9, 0x3A,
    0x82, 0x14, 0x13, 0x28, 0x1C, 0x47, 0x55, 0xE6,
    0xDC, 0x25, 0xB6, 0xCE, 0x5A, 0x12, 0xDA, 0x8A, 
    0xAB, 0x49, 0xFC, 0x9B, 0xBC, 0x86, 0xED, 0xE2
};

static FitSecPkiConfig pki_cfg = {
    {
        &station_id[0], sizeof(station_id),
        FS_NISTP256, &priv_key[0]
    },
    true, // enable repetition
    10
};


static const pchar_t * _o_canKeyPath = NULL;
static const pchar_t * _o_stationIdPath = NULL;
static const char * _o_dc = NULL;
static int    _o_reenr_delay = 5;
static int _o_skip_http = 0;
static uint32_t _o_http_timeout = 10;
static const char * _o_out = NULL;

static FSUT * ut = NULL;

static copt_t options[] = {
    { "K",  "canonical-key",  COPT_PATH,     &_o_canKeyPath,    "Canonical private key path" },
    { "I",  "station-id",     COPT_PATH,     &_o_stationIdPath, "Station identifier path" },
    { "D",  "dc",             COPT_STR,      &_o_dc,            "Override all DC URLs" },
    { "O",  "certs",          COPT_PATH,     &_o_out,           "Store received certificates" },
    { NULL, "reenrol-delay",  COPT_UINT,     &_o_reenr_delay,   "Re-enrolment delay [5 sec]"},
    { NULL, "http-dummy",     COPT_BOOL,     &_o_skip_http,     "do not perform any http requests"},
    { NULL, "http-timeout",   COPT_UINT,     &_o_http_timeout,  "HTTP timeout for PKI requests[10 sec]"},
    
    { NULL, NULL, COPT_END, NULL, NULL }
};

static int _options(MsgGenApp* app, int argc, char* argv[])
{
    int rc = 0;
    if (argc == 0) {
        coptions_help(stderr, "PKI", 0, options, "");
    }
    else {
        rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
        if (!COPT_ERC(rc)) {
            if(_o_canKeyPath){
                const char * ext = cstrpathextension(_o_canKeyPath);
                int fsize = 32;
                if(ext){
                    if(cstrequal(ext, "nist384")){
                        fsize = 48; pki_cfg.station.alg = FS_NISTP384;
                    } else if(cstrequal(ext, "bpool384")){
                        fsize = 48; pki_cfg.station.alg = FS_BRAINPOOLP384R1;
                    } else if(cstrequal(ext, "bpool256")){
                        pki_cfg.station.alg = FS_BRAINPOOLP256R1;
                    } else if(cstrequal(ext, "sm2")){
                        pki_cfg.station.alg = FS_SM2;
                    }
                }
                uint8_t * e = (uint8_t *)cstrnload((char*)&priv_key[0], sizeof(priv_key), _o_canKeyPath);
                if(e - &priv_key[0] != fsize){
                    perror(_o_canKeyPath);
                    rc = -1;
                }
            }
            if(_o_stationIdPath){
                uint8_t * e = (uint8_t *)cstrnload((char*)&station_id[0], sizeof(station_id), _o_stationIdPath);
                if(e - &station_id[0] != 16){
                    perror(_o_stationIdPath);
                    rc = -1;
                }
            }
            if(_o_out){
                _o_out = cstrdups(_o_out, 256);
            }
        }
    }
    return rc;
}

static int _store_cert=0;
static void pki_onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    if(event == FSEvent_CertStatus){
        if(_o_out && _store_cert){
            _store_cert = 0;
            FSHashedId8 digest = FSCertificate_Digest(params->certStateChange.certificate);
            const char * dir = "";
            if(params->certStateChange.to == FSCERT_INVALID){
                dir = "invalid/";
            }
            size_t len;
            const char * d = FSCertificate_Buffer(params->certStateChange.certificate, &len);
            if(d){
                char * end = cstrend(_o_out);
                sprintf(end, "/%s"cPrefixUint64"X.oer", dir, cint64_hton(digest));
                if (cstrnsave(d, len, _o_out)){
                    fprintf(stderr, "["cPrefixUint64"X]: stored as %s [%ld bytes]\n", cint64_hton(digest), _o_out, len);
                }else{
                    fprintf(stderr, "["cPrefixUint64"X]: failed to store as %s\n", cint64_hton(digest), _o_out);
                }
                pchar_t * ext = cstrpathextension(_o_out);
                FSCrypt * ce = FSCrypt_FindEngine(FitSec_GetConfig(e)->signEngine);
                if(ce){
                    const FSPrivateKey * k = FSCertificate_GetVerificationPrivateKey(params->certStateChange.certificate);
                    if(k){
                        uint8_t buf[256];
                        size_t len = FSKey_ExportPrivate(ce, k, buf);
                        if(len){
                            strcpy(ext, ".vkey");
                            cstrnsave((const char*)buf, len, _o_out);
                        }
                    }
                }
                ce = FSCrypt_FindEngine(FitSec_GetConfig(e)->encryptEngine);
                if(ce){
                    const FSPrivateKey * k = FSCertificate_GetEncryptionPrivateKey(params->certStateChange.certificate);
                    if(k){
                        uint8_t buf[256];
                        size_t len = FSKey_ExportPrivate(ce, k, buf);
                        if(len){
                            strcpy(ext, ".ekey");
                            cstrnsave((const char*)buf, len, _o_out);
                        }
                    }
                }
                *end = 0;
            }
        }
    }
}


static size_t _curl_receive(void const* buf, size_t eSize, size_t eCount, void* ptr) {
    FitSecPki* pki = (FitSecPki*)ptr;
    if (eCount > 0) {
        _store_cert = 1;
        int ret = FitSecPki_loadData(pki, buf, eSize * eCount);
        _store_cert = 0;
        if(ret != 0){
            fprintf(stderr, "PKI: %s\n", FitSec_ErrorMessage(ret));
            // error occured
            eCount = 0;
        }
    }
    return eCount;
}

static bool _process_http_request(FitSecPki* pki, const char* url, const char * body, size_t len)
{
    bool ret = true;
    printf("Request: %s\n", url);
    if(_o_skip_http){
        return false;
    }

    CURL* req = curl_easy_init();
    CURLcode res;
    if (req)
    {
        curl_easy_setopt(req, CURLOPT_URL, url);
        curl_easy_setopt(req, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(req, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(req, CURLOPT_WRITEFUNCTION, _curl_receive);
        curl_easy_setopt(req, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(req, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(req, CURLOPT_WRITEDATA, pki);
        curl_easy_setopt(req, CURLOPT_TIMEOUT, _o_http_timeout);
        if(body && len){
            curl_easy_setopt(req, CURLOPT_POST, 1L);
            curl_easy_setopt(req, CURLOPT_POSTFIELDSIZE, len);
            curl_easy_setopt(req, CURLOPT_POSTFIELDS, body);
            struct curl_slist *hs=NULL;
            hs = curl_slist_append(hs, "Content-Type: application/x-its-request");
            curl_easy_setopt(req, CURLOPT_HTTPHEADER, hs);
        }
        
        res = curl_easy_perform(req);
        if (res != CURLE_OK) {
            if(res != CURLE_WRITE_ERROR){
                fprintf(stderr, "curl_easy_operation() failed : %s\n", curl_easy_strerror(res));
            }
            ret = false;
        } else {
            long n;
            res = curl_easy_getinfo(req, CURLINFO_RESPONSE_CODE, &n);
            printf("ResponseCode: %ld\n", n);
            if(n != 200){
                ret = false;
            }
        }
    }
    curl_easy_cleanup(req);
    return ret;
}

FSCertificateParams params = { 0 };
static uint32_t _reenrolment_time = 0;
static size_t _fill_enr(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    if(_pki == NULL){
        _pki = FitSecPki_New(e, &pki_cfg);
    }

    if(FitSecPki_PrepareECRequest(_pki, &params, m)){
        char * url;
        size_t ulen;
        if(FSCertificate_GetDC(m->encryption.cert, &url, &ulen)){
            if (cstrnequal("http", url, 4)) {
                if(_process_http_request(_pki, url, m->message, m->messageSize)){
                    // send UT indication
                    if(ut){
                        char state = 1;
                        FSUT_EnqueueIndication(ut, FS_UtPkiTriggerInd, &state, 1);
                    }
                }else{
                    // enqueue repetition
                    if(_o_reenr_delay){
                        _reenrolment_time = time(NULL) + _o_reenr_delay;
                    }
                }
            }
        }else{
            fprintf(stderr, "Enrol: No DC found for CA cert " cPrefixUint64 "X\n", cint64_hton(FSCertificate_Digest(m->encryption.cert)));
        }
    }else{
        fprintf(stderr, "Enrol: %s\n", FitSec_ErrorMessage(m->status));
    }
    return 0;
}

static void pki_process_ea (MsgGenApp * app, FitSec * e)
{
    if(_reenrolment_time){
        if(time(NULL) >= _reenrolment_time){
            _reenrolment_time = 0;
            MsgGenApp_Send(_pki->e, &_enr);
        }
    }
}

static void pki_process_aa (MsgGenApp * app, FitSec * e)
{

}

static size_t _fill_auth(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    FSCertificateParams params = {
        .vKeyAlg = FS_NISTP256,
        .eKeyAlg = -1, // no enc key
        .startTime = unix2itstime32(time(NULL)),
        .durationType = dt_hours,
        .duration = 24,
        .appPermissions = {
            { FITSEC_AID_CAM, 3,  {.opaque = {0x01}} },  
        }
    };
 
    if(_pki == NULL){
        _pki = FitSecPki_New(e, &pki_cfg);
    }
    if(FitSecPki_PrepareATRequest(_pki, &params, m)){
        char * url;
        size_t ulen;
        if(FSCertificate_GetDC(m->encryption.cert, &url, &ulen)){
            if (cstrnequal("http", url, 4)) {
                if(_process_http_request(_pki, url, m->message, m->messageSize)){
                    // send UT indication
                    if(ut){
                        char state = 1;
                        FSUT_EnqueueIndication(ut, FS_UtPkiTriggerInd, &state, 1);
                    }
                }
            }
        }else{
            fprintf(stderr, "Auth: No DC found for CA cert " cPrefixUint64 "x\n", cint64_hton(FSCertificate_Digest(m->encryption.cert)));
        }
    }else{
        fprintf(stderr, "Auth: %s\n", FitSec_ErrorMessage(m->status));
    }
    return 0;
}

static int  pki_ut_handler(FSUT* _ut, void* ptr, FSUT_Message* m, int * psize)
{
    ut = _ut;
    FitSec * e = ptr;
    if(_pki == NULL){
        _pki = FitSecPki_New(e, &pki_cfg);
    }
    switch (m->code){
        case FS_UtGenerateInnerEcRequest:
            fprintf(stderr, "======================================== UtGenerateInnerEcRequest[%u]\n", m->code);
            MsgGenApp_Send(_pki->e, &_enr);
            m->result.code = FS_UtGenerateInnerEcResult;
            break;
        case FS_UtGenerateInnerAtRequest:
            fprintf(stderr, "======================================== UtGenerateInnerAtRequest[%u]\n", m->code);
            MsgGenApp_Send(_pki->e, &_auth);
            m->result.code = FS_UtGenerateInnerEcResult;
            break;
        default:
            return 0;
    }
    m->result.result = 1;
    *psize = sizeof(m->result);
    fprintf(stderr, "======================================== END [%u=%u]\n", m->code, m->result.result);
    return 1;
}
