/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_TrafficConditionSubCauseCode_H_
#define	_TrafficConditionSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TrafficConditionSubCauseCode {
	TrafficConditionSubCauseCode_unavailable	= 0,
	TrafficConditionSubCauseCode_increasedVolumeOfTraffic	= 1,
	TrafficConditionSubCauseCode_trafficJamSlowlyIncreasing	= 2,
	TrafficConditionSubCauseCode_trafficJamIncreasing	= 3,
	TrafficConditionSubCauseCode_trafficJamStronglyIncreasing	= 4,
	TrafficConditionSubCauseCode_trafficJam	= 5,
	TrafficConditionSubCauseCode_trafficJamSlightlyDecreasing	= 6,
	TrafficConditionSubCauseCode_trafficJamDecreasing	= 7,
	TrafficConditionSubCauseCode_trafficJamStronglyDecreasing	= 8,
	TrafficConditionSubCauseCode_trafficJamStable	= 9
} e_TrafficConditionSubCauseCode;

/* TrafficConditionSubCauseCode */
typedef long	 TrafficConditionSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TrafficConditionSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TrafficConditionSubCauseCode;
asn_struct_free_f TrafficConditionSubCauseCode_free;
asn_constr_check_f TrafficConditionSubCauseCode_constraint;
per_type_decoder_f TrafficConditionSubCauseCode_decode_uper;
per_type_encoder_f TrafficConditionSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TrafficConditionSubCauseCode_H_ */
#include <asn_internal.h>
