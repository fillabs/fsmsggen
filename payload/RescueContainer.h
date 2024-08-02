/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "LightBarSirenInUse.h"
#include <constr_SEQUENCE.h>
#ifndef	_RescueContainer_H_
#define	_RescueContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RescueContainer */
typedef struct RescueContainer {
	LightBarSirenInUse_t	 lightBarSirenInUse;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RescueContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RescueContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_RescueContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_RescueContainer_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RescueContainer_H_ */
#include <asn_internal.h>
