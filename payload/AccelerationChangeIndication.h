/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "AccelerationChange.h"
#include "DeltaTimeTenthOfSecond.h"
#include <constr_SEQUENCE.h>
#ifndef	_AccelerationChangeIndication_H_
#define	_AccelerationChangeIndication_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AccelerationChangeIndication */
typedef struct AccelerationChangeIndication {
	AccelerationChange_t	 accelOrDecel;
	DeltaTimeTenthOfSecond_t	 actionDeltaTime;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AccelerationChangeIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AccelerationChangeIndication;
extern asn_SEQUENCE_specifics_t asn_SPC_AccelerationChangeIndication_specs_1;
extern asn_TYPE_member_t asn_MBR_AccelerationChangeIndication_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _AccelerationChangeIndication_H_ */
#include <asn_internal.h>
