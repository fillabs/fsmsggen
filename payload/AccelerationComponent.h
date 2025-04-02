/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "AccelerationValue.h"
#include "AccelerationConfidence.h"
#include <constr_SEQUENCE.h>
#ifndef	_AccelerationComponent_H_
#define	_AccelerationComponent_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AccelerationComponent */
typedef struct AccelerationComponent {
	AccelerationValue_t	 value;
	AccelerationConfidence_t	 confidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AccelerationComponent_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AccelerationComponent;
extern asn_SEQUENCE_specifics_t asn_SPC_AccelerationComponent_specs_1;
extern asn_TYPE_member_t asn_MBR_AccelerationComponent_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _AccelerationComponent_H_ */
#include <asn_internal.h>
