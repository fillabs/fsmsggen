/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_StationaryVehicleSubCauseCode_H_
#define	_StationaryVehicleSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum StationaryVehicleSubCauseCode {
	StationaryVehicleSubCauseCode_unavailable	= 0,
	StationaryVehicleSubCauseCode_humanProblem	= 1,
	StationaryVehicleSubCauseCode_vehicleBreakdown	= 2,
	StationaryVehicleSubCauseCode_postCrash	= 3,
	StationaryVehicleSubCauseCode_publicTransportStop	= 4,
	StationaryVehicleSubCauseCode_carryingDangerousGoods	= 5,
	StationaryVehicleSubCauseCode_vehicleOnFire	= 6
} e_StationaryVehicleSubCauseCode;

/* StationaryVehicleSubCauseCode */
typedef long	 StationaryVehicleSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_StationaryVehicleSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_StationaryVehicleSubCauseCode;
asn_struct_free_f StationaryVehicleSubCauseCode_free;
asn_constr_check_f StationaryVehicleSubCauseCode_constraint;
per_type_decoder_f StationaryVehicleSubCauseCode_decode_uper;
per_type_encoder_f StationaryVehicleSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _StationaryVehicleSubCauseCode_H_ */
#include <asn_internal.h>
