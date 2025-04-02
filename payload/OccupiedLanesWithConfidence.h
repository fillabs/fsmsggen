/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "MetaInformation.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>
#ifndef	_OccupiedLanesWithConfidence_H_
#define	_OccupiedLanesWithConfidence_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LanePositionOptions;
struct MapPosition;

/* OccupiedLanesWithConfidence */
typedef struct OccupiedLanesWithConfidence {
	struct OccupiedLanesWithConfidence__lanePositionBased {
		A_SEQUENCE_OF(struct LanePositionOptions) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} lanePositionBased;
	struct OccupiedLanesWithConfidence__mapBased {
		A_SEQUENCE_OF(struct MapPosition) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *mapBased;
	MetaInformation_t	 confidence;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OccupiedLanesWithConfidence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OccupiedLanesWithConfidence;
extern asn_SEQUENCE_specifics_t asn_SPC_OccupiedLanesWithConfidence_specs_1;
extern asn_TYPE_member_t asn_MBR_OccupiedLanesWithConfidence_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LanePositionOptions.h"
#include "MapPosition.h"

#endif	/* _OccupiedLanesWithConfidence_H_ */
#include <asn_internal.h>
