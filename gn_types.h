#ifndef gn_types_h
#define gn_types_h

#include "cbyteswap.h"
#include <inttypes.h>

typedef struct GNBasicHeader GNBasicHeader;
__PACKED__(struct GNBasicHeader {
    unsigned int version : 4;
    unsigned int nextHeader : 4;
    uint8_t      reserved;
    uint8_t      lifeTime;
    uint8_t      routerHopLimit;
});

typedef struct GNCommonHeader GNCommonHeader;
__PACKED__(struct GNCommonHeader {
    uint8_t         nextHeader;
//    unsigned int    reserved : 4; // skipped. included in nextHeader
    uint8_t         headerType;
    uint8_t         trafficClass;
    uint8_t         flags;
    uint16_t        plLength; // The Codec shall set the length of the paylaod if present
    uint8_t         maxHopLimit;
    uint8_t         reserved2;
});

typedef struct GNAddress GNAddress;
__PACKED__(struct GNAddress {
    uint16_t aType;
    uint8_t  addr[6];
});

typedef struct LongPosVector LongPosVector;
__PACKED__(struct LongPosVector {
    GNAddress  gnAddr;
    uint32_t   timestamp;
    int32_t    latitude;
    int32_t    longitude;
    int16_t    accAndSpeed;
    uint16_t   heading;
});

typedef struct ShortPosVector ShortPosVector;
__PACKED__(struct ShortPosVector {
    GNAddress  gnAddr;
    uint32_t   timestamp;
    int32_t    latitude;
    int32_t    longitude;
});

typedef struct GUCHeader GUCHeader;
__PACKED__(struct GUCHeader {
    uint16_t         sequenceNumber;
    uint16_t         reserved;
    LongPosVector    srcPosVector;
    ShortPosVector   dstPosVector;
});

typedef struct GNTSBHeader GNTSBHeader;
__PACKED__(struct GNTSBHeader {
    uint16_t         sequenceNumber;
    uint16_t         reserved;
    LongPosVector    srcPosVector;
});

typedef struct GNSHBHeader GNSHBHeader;
__PACKED__(struct GNSHBHeader {
    LongPosVector    srcPosVector;
    uint32_t         reserved;
});

typedef struct GBCHeader GBCHeader;
__PACKED__(struct GBCHeader {
    uint16_t         sequenceNumber;
    uint16_t         reserved;
    LongPosVector    srcPosVector;
    uint32_t         latitude;
    uint32_t         longitude;
    uint16_t         distanceA;
    uint16_t         distanceB;
    uint16_t         angle;
    uint16_t         reserved2;    
});

typedef struct GNBeaconHeader GNBeaconHeader;
__PACKED__(struct GNBeaconHeader {
    LongPosVector   srcPosVector;
});

typedef struct LSReqHeader LSReqHeader;
__PACKED__(struct LSReqHeader {
    uint16_t         sequenceNumber;
    uint16_t         reserved;
    LongPosVector    srcPosVector;
    GNAddress        reqAddr;
});

typedef struct LSRepHeader LSRepHeader;
__PACKED__(struct LSRepHeader {
    uint16_t         sequenceNumber;
    uint16_t         reserved;
    LongPosVector    srcPosVector;
    ShortPosVector   dstPosVector;
});

typedef union GNExtendedHeader GNExtendedHeader;
__PACKED__(union GNExtendedHeader {
    GNSHBHeader        shb;
    GNTSBHeader        tsb;
    GUCHeader          guc;
    GBCHeader          gbc;
    GNBeaconHeader     beacon;
    LSReqHeader        lsreq;
    LSRepHeader        lsrep;
});

#endif
