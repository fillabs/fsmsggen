/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PerceivedObjectContainer"
 * 	found in "asn1/CPM-PerceivedObjectContainer.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#ifndef	_PerceivedObjects_H_
#define	_PerceivedObjects_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PerceivedObject;

/* PerceivedObjects */
typedef struct PerceivedObjects {
	A_SEQUENCE_OF(struct PerceivedObject) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PerceivedObjects_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PerceivedObjects;
extern asn_SET_OF_specifics_t asn_SPC_PerceivedObjects_specs_1;
extern asn_TYPE_member_t asn_MBR_PerceivedObjects_1[1];
extern asn_per_constraints_t asn_PER_type_PerceivedObjects_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PerceivedObject.h"

#endif	/* _PerceivedObjects_H_ */
#include <asn_internal.h>
