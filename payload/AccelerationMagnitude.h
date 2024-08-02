/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "AccelerationMagnitudeValue.h"
#include "AccelerationConfidence.h"
#include <constr_SEQUENCE.h>
#ifndef	_AccelerationMagnitude_H_
#define	_AccelerationMagnitude_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AccelerationMagnitude */
typedef struct AccelerationMagnitude {
	AccelerationMagnitudeValue_t	 accelerationMagnitudeValue;
	AccelerationConfidence_t	 accelerationConfidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AccelerationMagnitude_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AccelerationMagnitude;
extern asn_SEQUENCE_specifics_t asn_SPC_AccelerationMagnitude_specs_1;
extern asn_TYPE_member_t asn_MBR_AccelerationMagnitude_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _AccelerationMagnitude_H_ */
#include <asn_internal.h>
