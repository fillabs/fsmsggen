/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_RoadworksSubCauseCode_H_
#define	_RoadworksSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RoadworksSubCauseCode {
	RoadworksSubCauseCode_unavailable	= 0,
	RoadworksSubCauseCode_majorRoadworks	= 1,
	RoadworksSubCauseCode_roadMarkingWork	= 2,
	RoadworksSubCauseCode_slowMovingRoadMaintenance	= 3,
	RoadworksSubCauseCode_shortTermStationaryRoadworks	= 4,
	RoadworksSubCauseCode_streetCleaning	= 5,
	RoadworksSubCauseCode_winterService	= 6,
	RoadworksSubCauseCode_setupPhase	= 7,
	RoadworksSubCauseCode_remodellingPhase	= 8,
	RoadworksSubCauseCode_dismantlingPhase	= 9
} e_RoadworksSubCauseCode;

/* RoadworksSubCauseCode */
typedef long	 RoadworksSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RoadworksSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RoadworksSubCauseCode;
asn_struct_free_f RoadworksSubCauseCode_free;
asn_constr_check_f RoadworksSubCauseCode_constraint;
per_type_decoder_f RoadworksSubCauseCode_decode_uper;
per_type_encoder_f RoadworksSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _RoadworksSubCauseCode_H_ */
#include <asn_internal.h>
