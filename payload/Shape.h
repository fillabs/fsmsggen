/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "RectangularShape.h"
#include "CircularShape.h"
#include "PolygonalShape.h"
#include "EllipticalShape.h"
#include "RadialShape.h"
#include "RadialShapes.h"
#include <constr_CHOICE.h>
#ifndef	_Shape_H_
#define	_Shape_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Shape_PR {
	Shape_PR_NOTHING,	/* No components present */
	Shape_PR_rectangular,
	Shape_PR_circular,
	Shape_PR_polygonal,
	Shape_PR_elliptical,
	Shape_PR_radial,
	Shape_PR_radialShapes
	/* Extensions may appear below */
	
} Shape_PR;

/* Shape */
typedef struct Shape {
	Shape_PR present;
	union Shape_u {
		RectangularShape_t	 rectangular;
		CircularShape_t	 circular;
		PolygonalShape_t	 polygonal;
		EllipticalShape_t	 elliptical;
		RadialShape_t	 radial;
		RadialShapes_t	 radialShapes;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Shape_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Shape;
extern asn_CHOICE_specifics_t asn_SPC_Shape_specs_1;
extern asn_TYPE_member_t asn_MBR_Shape_1[6];
extern asn_per_constraints_t asn_PER_type_Shape_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Shape_H_ */
#include <asn_internal.h>
