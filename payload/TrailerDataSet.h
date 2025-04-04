/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-OriginatingStationContainers"
 * 	found in "asn1/CPM-OriginatingStationContainers.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#ifndef	_TrailerDataSet_H_
#define	_TrailerDataSet_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TrailerData;

/* TrailerDataSet */
typedef struct TrailerDataSet {
	A_SEQUENCE_OF(struct TrailerData) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TrailerDataSet_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TrailerDataSet;
extern asn_SET_OF_specifics_t asn_SPC_TrailerDataSet_specs_1;
extern asn_TYPE_member_t asn_MBR_TrailerDataSet_1[1];
extern asn_per_constraints_t asn_PER_type_TrailerDataSet_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TrailerData.h"

#endif	/* _TrailerDataSet_H_ */
#include <asn_internal.h>
