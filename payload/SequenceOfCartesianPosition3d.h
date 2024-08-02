/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#ifndef	_SequenceOfCartesianPosition3d_H_
#define	_SequenceOfCartesianPosition3d_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CartesianPosition3d;

/* SequenceOfCartesianPosition3d */
typedef struct SequenceOfCartesianPosition3d {
	A_SEQUENCE_OF(struct CartesianPosition3d) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfCartesianPosition3d_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfCartesianPosition3d;
extern asn_SET_OF_specifics_t asn_SPC_SequenceOfCartesianPosition3d_specs_1;
extern asn_TYPE_member_t asn_MBR_SequenceOfCartesianPosition3d_1[1];
extern asn_per_constraints_t asn_PER_type_SequenceOfCartesianPosition3d_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CartesianPosition3d.h"

#endif	/* _SequenceOfCartesianPosition3d_H_ */
#include <asn_internal.h>
