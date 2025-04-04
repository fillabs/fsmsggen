/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/DENM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "Traces.h"
#include "RoadType.h"
#include <constr_SEQUENCE.h>
#ifndef	_LocationContainer_H_
#define	_LocationContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Speed;
struct Wgs84Angle;
struct GeneralizedLanePositions;
struct OccupiedLanesWithConfidence;
struct IvimReferences;
struct MapReferences;
struct TracesExtended;
struct PathPredictedList;

/* LocationContainer */
typedef struct LocationContainer {
	struct Speed	*eventSpeed;	/* OPTIONAL */
	struct Wgs84Angle	*eventPositionHeading;	/* OPTIONAL */
	Traces_t	 detectionZonesToEventPosition;
	RoadType_t	*roadType;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct LocationContainer__ext1 {
		struct GeneralizedLanePositions	*lanePositions;	/* OPTIONAL */
		struct OccupiedLanesWithConfidence	*occupiedLanes;	/* OPTIONAL */
		struct IvimReferences	*linkedIvims;	/* OPTIONAL */
		struct MapReferences	*linkedMapems;	/* OPTIONAL */
		struct TracesExtended	*detectionZonesToSpecifiedEventPoint;	/* OPTIONAL */
		struct PathPredictedList	*predictedPaths;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LocationContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LocationContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_LocationContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_LocationContainer_1[5];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Speed.h"
#include "Wgs84Angle.h"
#include "GeneralizedLanePositions.h"
#include "OccupiedLanesWithConfidence.h"
#include "IvimReferences.h"
#include "MapReferences.h"
#include "TracesExtended.h"
#include "PathPredictedList.h"

#endif	/* _LocationContainer_H_ */
#include <asn_internal.h>
