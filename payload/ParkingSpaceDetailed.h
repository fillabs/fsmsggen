/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "Identifier2B.h"
#include "ParkingSpaceStatus.h"
#include "ParkingAreaArrangementType.h"
#include "ParkingOccupancyInfo.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include "ParkingReservationType.h"
#include <constr_SEQUENCE.h>
#ifndef	_ParkingSpaceDetailed_H_
#define	_ParkingSpaceDetailed_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DeltaReferencePosition;
struct DeltaPositions;
struct Wgs84Angle;

/* ParkingSpaceDetailed */
typedef struct ParkingSpaceDetailed {
	Identifier2B_t	 id;
	struct DeltaReferencePosition	*location;	/* OPTIONAL */
	ParkingSpaceStatus_t	 status;
	ParkingAreaArrangementType_t	*arrangementType;	/* OPTIONAL */
	struct DeltaPositions	*boundary;	/* OPTIONAL */
	struct Wgs84Angle	*orientation;	/* OPTIONAL */
	ParkingOccupancyInfo_t	 occupancyRule;
	Identifier2B_t	*chargingStationId;	/* OPTIONAL */
	Identifier2B_t	*accessViaLane;	/* OPTIONAL */
	struct ParkingSpaceDetailed__accessViaParkingSpaces {
		A_SEQUENCE_OF(Identifier2B_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *accessViaParkingSpaces;
	struct ParkingSpaceDetailed__reservationType {
		A_SEQUENCE_OF(ParkingReservationType_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *reservationType;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ParkingSpaceDetailed_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ParkingSpaceDetailed;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DeltaReferencePosition.h"
#include "DeltaPositions.h"
#include "Wgs84Angle.h"

#endif	/* _ParkingSpaceDetailed_H_ */
#include <asn_internal.h>
