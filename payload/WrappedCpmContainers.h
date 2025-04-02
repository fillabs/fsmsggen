/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/CPM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#ifndef	_WrappedCpmContainers_H_
#define	_WrappedCpmContainers_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct WrappedCpmContainer;

/* WrappedCpmContainers */
typedef struct WrappedCpmContainers {
	A_SEQUENCE_OF(struct WrappedCpmContainer) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} WrappedCpmContainers_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_WrappedCpmContainers;
extern asn_SET_OF_specifics_t asn_SPC_WrappedCpmContainers_specs_1;
extern asn_TYPE_member_t asn_MBR_WrappedCpmContainers_1[1];
extern asn_per_constraints_t asn_PER_type_WrappedCpmContainers_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "WrappedCpmContainer.h"

#endif	/* _WrappedCpmContainers_H_ */
#include <asn_internal.h>
