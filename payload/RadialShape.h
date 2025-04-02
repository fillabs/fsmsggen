/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "StandardLength12b.h"
#include "CartesianAngleValue.h"
#include <constr_SEQUENCE.h>
#ifndef	_RadialShape_H_
#define	_RadialShape_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CartesianPosition3d;

/* RadialShape */
typedef struct RadialShape {
	struct CartesianPosition3d	*shapeReferencePoint;	/* OPTIONAL */
	StandardLength12b_t	 range;
	CartesianAngleValue_t	 horizontalOpeningAngleStart;
	CartesianAngleValue_t	 horizontalOpeningAngleEnd;
	CartesianAngleValue_t	*verticalOpeningAngleStart;	/* OPTIONAL */
	CartesianAngleValue_t	*verticalOpeningAngleEnd;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadialShape_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadialShape;
extern asn_SEQUENCE_specifics_t asn_SPC_RadialShape_specs_1;
extern asn_TYPE_member_t asn_MBR_RadialShape_1[6];
extern asn_per_constraints_t asn_PER_type_RadialShape_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CartesianPosition3d.h"

#endif	/* _RadialShape_H_ */
#include <asn_internal.h>
