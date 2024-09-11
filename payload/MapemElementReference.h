/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <constr_SEQUENCE.h>
#ifndef	_MapemElementReference_H_
#define	_MapemElementReference_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MapReference;
struct MapemLaneList;
struct MapemConnectionList;

/* MapemElementReference */
typedef struct MapemElementReference {
	struct MapReference	*mapReference;	/* OPTIONAL */
	struct MapemLaneList	*laneIds;	/* OPTIONAL */
	struct MapemConnectionList	*connectionIds;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MapemElementReference_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MapemElementReference;
extern asn_SEQUENCE_specifics_t asn_SPC_MapemElementReference_specs_1;
extern asn_TYPE_member_t asn_MBR_MapemElementReference_1[3];
extern asn_per_constraints_t asn_PER_type_MapemElementReference_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MapReference.h"
#include "MapemLaneList.h"
#include "MapemConnectionList.h"

#endif	/* _MapemElementReference_H_ */
#include <asn_internal.h>
