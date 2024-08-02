/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "Identifier1B.h"
#include "CartesianCoordinateSmall.h"
#include "RadialShapesList.h"
#include <constr_SEQUENCE.h>
#ifndef	_RadialShapes_H_
#define	_RadialShapes_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RadialShapes */
typedef struct RadialShapes {
	Identifier1B_t	 refPointId;
	CartesianCoordinateSmall_t	 xCoordinate;
	CartesianCoordinateSmall_t	 yCoordinate;
	CartesianCoordinateSmall_t	*zCoordinate;	/* OPTIONAL */
	RadialShapesList_t	 radialShapesList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadialShapes_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadialShapes;
extern asn_SEQUENCE_specifics_t asn_SPC_RadialShapes_specs_1;
extern asn_TYPE_member_t asn_MBR_RadialShapes_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _RadialShapes_H_ */
#include <asn_internal.h>
