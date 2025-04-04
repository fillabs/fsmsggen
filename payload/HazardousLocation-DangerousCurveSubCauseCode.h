/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_HazardousLocation_DangerousCurveSubCauseCode_H_
#define	_HazardousLocation_DangerousCurveSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HazardousLocation_DangerousCurveSubCauseCode {
	HazardousLocation_DangerousCurveSubCauseCode_unavailable	= 0,
	HazardousLocation_DangerousCurveSubCauseCode_dangerousLeftTurnCurve	= 1,
	HazardousLocation_DangerousCurveSubCauseCode_dangerousRightTurnCurve	= 2,
	HazardousLocation_DangerousCurveSubCauseCode_multipleCurvesStartingWithUnknownTurningDirection	= 3,
	HazardousLocation_DangerousCurveSubCauseCode_multipleCurvesStartingWithLeftTurn	= 4,
	HazardousLocation_DangerousCurveSubCauseCode_multipleCurvesStartingWithRightTurn	= 5
} e_HazardousLocation_DangerousCurveSubCauseCode;

/* HazardousLocation-DangerousCurveSubCauseCode */
typedef long	 HazardousLocation_DangerousCurveSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_HazardousLocation_DangerousCurveSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_HazardousLocation_DangerousCurveSubCauseCode;
asn_struct_free_f HazardousLocation_DangerousCurveSubCauseCode_free;
asn_constr_check_f HazardousLocation_DangerousCurveSubCauseCode_constraint;
per_type_decoder_f HazardousLocation_DangerousCurveSubCauseCode_decode_uper;
per_type_encoder_f HazardousLocation_DangerousCurveSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _HazardousLocation_DangerousCurveSubCauseCode_H_ */
#include <asn_internal.h>
