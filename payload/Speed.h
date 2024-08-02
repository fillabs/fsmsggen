/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "SpeedValue.h"
#include "SpeedConfidence.h"
#include <constr_SEQUENCE.h>
#ifndef	_Speed_H_
#define	_Speed_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Speed */
typedef struct Speed {
	SpeedValue_t	 speedValue;
	SpeedConfidence_t	 speedConfidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Speed_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Speed;
extern asn_SEQUENCE_specifics_t asn_SPC_Speed_specs_1;
extern asn_TYPE_member_t asn_MBR_Speed_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _Speed_H_ */
#include <asn_internal.h>
