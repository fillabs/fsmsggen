/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "GenerationDeltaTime.h"
#include "CamParameters.h"
#include <constr_SEQUENCE.h>
#ifndef	_CamPayload_H_
#define	_CamPayload_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CamPayload */
typedef struct CamPayload {
	GenerationDeltaTime_t	 generationDeltaTime;
	CamParameters_t	 camParameters;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CamPayload_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CamPayload;
extern asn_SEQUENCE_specifics_t asn_SPC_CamPayload_specs_1;
extern asn_TYPE_member_t asn_MBR_CamPayload_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _CamPayload_H_ */
#include <asn_internal.h>
