/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_RescueAndRecoveryWorkInProgressSubCauseCode_H_
#define	_RescueAndRecoveryWorkInProgressSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RescueAndRecoveryWorkInProgressSubCauseCode {
	RescueAndRecoveryWorkInProgressSubCauseCode_unavailable	= 0,
	RescueAndRecoveryWorkInProgressSubCauseCode_emergencyVehicles	= 1,
	RescueAndRecoveryWorkInProgressSubCauseCode_rescueHelicopterLanding	= 2,
	RescueAndRecoveryWorkInProgressSubCauseCode_policeActivityOngoing	= 3,
	RescueAndRecoveryWorkInProgressSubCauseCode_medicalEmergencyOngoing	= 4,
	RescueAndRecoveryWorkInProgressSubCauseCode_childAbductionInProgress	= 5,
	RescueAndRecoveryWorkInProgressSubCauseCode_prioritizedVehicle	= 6,
	RescueAndRecoveryWorkInProgressSubCauseCode_rescueAndRecoveryVehicle	= 7
} e_RescueAndRecoveryWorkInProgressSubCauseCode;

/* RescueAndRecoveryWorkInProgressSubCauseCode */
typedef long	 RescueAndRecoveryWorkInProgressSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RescueAndRecoveryWorkInProgressSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RescueAndRecoveryWorkInProgressSubCauseCode;
asn_struct_free_f RescueAndRecoveryWorkInProgressSubCauseCode_free;
asn_constr_check_f RescueAndRecoveryWorkInProgressSubCauseCode_constraint;
per_type_decoder_f RescueAndRecoveryWorkInProgressSubCauseCode_decode_uper;
per_type_encoder_f RescueAndRecoveryWorkInProgressSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _RescueAndRecoveryWorkInProgressSubCauseCode_H_ */
#include <asn_internal.h>
