/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "PolygonalLine.h"
#include <constr_SEQUENCE.h>
#ifndef	_EHorizonLocationSharingContainer_H_
#define	_EHorizonLocationSharingContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ConfidenceLevels;
struct BasicLaneConfiguration;
struct MetaInformation;

/* EHorizonLocationSharingContainer */
typedef struct EHorizonLocationSharingContainer {
	PolygonalLine_t	 segmentAhead;
	struct ConfidenceLevels	*nodeProbabilities;	/* OPTIONAL */
	PolygonalLine_t	 segmentBehind;
	struct BasicLaneConfiguration	*laneLevelDetails;	/* OPTIONAL */
	struct MetaInformation	*segmentSource;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EHorizonLocationSharingContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EHorizonLocationSharingContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_EHorizonLocationSharingContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_EHorizonLocationSharingContainer_1[5];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ConfidenceLevels.h"
#include "BasicLaneConfiguration.h"
#include "MetaInformation.h"

#endif	/* _EHorizonLocationSharingContainer_H_ */
#include <asn_internal.h>
