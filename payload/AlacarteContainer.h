/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/DENM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "LanePosition.h"
#include "Temperature.h"
#include "PositioningSolutionType.h"
#include <constr_SEQUENCE.h>
#ifndef	_AlacarteContainer_H_
#define	_AlacarteContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ImpactReductionContainer;
struct RoadWorksContainerExtended;
struct StationaryVehicleContainer;
struct RoadConfigurationContainer;
struct PreCrashContainer;

/* AlacarteContainer */
typedef struct AlacarteContainer {
	LanePosition_t	*lanePosition;	/* OPTIONAL */
	struct ImpactReductionContainer	*impactReduction;	/* OPTIONAL */
	Temperature_t	*externalTemperature;	/* OPTIONAL */
	struct RoadWorksContainerExtended	*roadWorks;	/* OPTIONAL */
	PositioningSolutionType_t	*positioningSolution;	/* OPTIONAL */
	struct StationaryVehicleContainer	*stationaryVehicle;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct AlacarteContainer__ext1 {
		struct RoadConfigurationContainer	*roadConfiguration;	/* OPTIONAL */
		struct PreCrashContainer	*preCrash;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AlacarteContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AlacarteContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_AlacarteContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_AlacarteContainer_1[7];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ImpactReductionContainer.h"
#include "RoadWorksContainerExtended.h"
#include "StationaryVehicleContainer.h"
#include "RoadConfigurationContainer.h"
#include "PreCrashContainer.h"

#endif	/* _AlacarteContainer_H_ */
#include <asn_internal.h>
