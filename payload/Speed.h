/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
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
