/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "CauseCodeChoice.h"
#include <constr_SEQUENCE.h>
#ifndef	_CauseCodeV2_H_
#define	_CauseCodeV2_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CauseCodeV2 */
typedef struct CauseCodeV2 {
	CauseCodeChoice_t	 ccAndScc;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CauseCodeV2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CauseCodeV2;
extern asn_SEQUENCE_specifics_t asn_SPC_CauseCodeV2_specs_1;
extern asn_TYPE_member_t asn_MBR_CauseCodeV2_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _CauseCodeV2_H_ */
#include <asn_internal.h>
