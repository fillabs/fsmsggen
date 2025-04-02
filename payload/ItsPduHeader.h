/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "OrdinalNumber1B.h"
#include "MessageId.h"
#include "StationId.h"
#include <constr_SEQUENCE.h>
#ifndef	_ItsPduHeader_H_
#define	_ItsPduHeader_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ItsPduHeader */
typedef struct ItsPduHeader {
	OrdinalNumber1B_t	 protocolVersion;
	MessageId_t	 messageId;
	StationId_t	 stationId;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ItsPduHeader_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ItsPduHeader;
extern asn_SEQUENCE_specifics_t asn_SPC_ItsPduHeader_specs_1;
extern asn_TYPE_member_t asn_MBR_ItsPduHeader_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _ItsPduHeader_H_ */
#include <asn_internal.h>
