/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "LanePosition.h"
#include "LaneType.h"
#include "LanePositionAndType.h"
#include "LanePositionWithLateralDetails.h"
#include "TrafficIslandPosition.h"
#include <constr_CHOICE.h>
#ifndef	_LanePositionOptions_H_
#define	_LanePositionOptions_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LanePositionOptions_PR {
	LanePositionOptions_PR_NOTHING,	/* No components present */
	LanePositionOptions_PR_simplelanePosition,
	LanePositionOptions_PR_simpleLaneType,
	LanePositionOptions_PR_detailedlanePosition,
	LanePositionOptions_PR_lanePositionWithLateralDetails,
	LanePositionOptions_PR_trafficIslandPosition
	/* Extensions may appear below */
	
} LanePositionOptions_PR;

/* LanePositionOptions */
typedef struct LanePositionOptions {
	LanePositionOptions_PR present;
	union LanePositionOptions_u {
		LanePosition_t	 simplelanePosition;
		LaneType_t	 simpleLaneType;
		LanePositionAndType_t	 detailedlanePosition;
		LanePositionWithLateralDetails_t	 lanePositionWithLateralDetails;
		TrafficIslandPosition_t	 trafficIslandPosition;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LanePositionOptions_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LanePositionOptions;
extern asn_CHOICE_specifics_t asn_SPC_LanePositionOptions_specs_1;
extern asn_TYPE_member_t asn_MBR_LanePositionOptions_1[5];
extern asn_per_constraints_t asn_PER_type_LanePositionOptions_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LanePositionOptions_H_ */
#include <asn_internal.h>
