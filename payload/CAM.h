/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "ItsPduHeader.h"
#include "CamPayload.h"
#include <constr_SEQUENCE.h>
#ifndef	_CAM_H_
#define	_CAM_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CAM */
typedef struct CAM {
	ItsPduHeader_t	 header;
	CamPayload_t	 cam;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CAM_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CAM;

#ifdef __cplusplus
}
#endif

#endif	/* _CAM_H_ */
#include <asn_internal.h>
