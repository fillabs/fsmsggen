/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_VehicleBreakdownSubCauseCode_H_
#define	_VehicleBreakdownSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VehicleBreakdownSubCauseCode {
	VehicleBreakdownSubCauseCode_unavailable	= 0,
	VehicleBreakdownSubCauseCode_lackOfFuel	= 1,
	VehicleBreakdownSubCauseCode_lackOfBatteryPower	= 2,
	VehicleBreakdownSubCauseCode_engineProblem	= 3,
	VehicleBreakdownSubCauseCode_transmissionProblem	= 4,
	VehicleBreakdownSubCauseCode_engineCoolingProblem	= 5,
	VehicleBreakdownSubCauseCode_brakingSystemProblem	= 6,
	VehicleBreakdownSubCauseCode_steeringProblem	= 7,
	VehicleBreakdownSubCauseCode_tyrePuncture	= 8,
	VehicleBreakdownSubCauseCode_tyrePressureProblem	= 9,
	VehicleBreakdownSubCauseCode_vehicleOnFire	= 10
} e_VehicleBreakdownSubCauseCode;

/* VehicleBreakdownSubCauseCode */
typedef long	 VehicleBreakdownSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VehicleBreakdownSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VehicleBreakdownSubCauseCode;
asn_struct_free_f VehicleBreakdownSubCauseCode_free;
asn_constr_check_f VehicleBreakdownSubCauseCode_constraint;
per_type_decoder_f VehicleBreakdownSubCauseCode_decode_uper;
per_type_encoder_f VehicleBreakdownSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleBreakdownSubCauseCode_H_ */
#include <asn_internal.h>
