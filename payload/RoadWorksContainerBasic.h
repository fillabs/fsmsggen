/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "RoadworksSubCauseCode.h"
#include "LightBarSirenInUse.h"
#include <constr_SEQUENCE.h>
#ifndef	_RoadWorksContainerBasic_H_
#define	_RoadWorksContainerBasic_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ClosedLanes;

/* RoadWorksContainerBasic */
typedef struct RoadWorksContainerBasic {
	RoadworksSubCauseCode_t	*roadworksSubCauseCode;	/* OPTIONAL */
	LightBarSirenInUse_t	 lightBarSirenInUse;
	struct ClosedLanes	*closedLanes;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RoadWorksContainerBasic_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RoadWorksContainerBasic;
extern asn_SEQUENCE_specifics_t asn_SPC_RoadWorksContainerBasic_specs_1;
extern asn_TYPE_member_t asn_MBR_RoadWorksContainerBasic_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ClosedLanes.h"

#endif	/* _RoadWorksContainerBasic_H_ */
#include <asn_internal.h>
