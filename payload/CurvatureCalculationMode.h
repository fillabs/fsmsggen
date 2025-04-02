/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_CurvatureCalculationMode_H_
#define	_CurvatureCalculationMode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CurvatureCalculationMode {
	CurvatureCalculationMode_yawRateUsed	= 0,
	CurvatureCalculationMode_yawRateNotUsed	= 1,
	CurvatureCalculationMode_unavailable	= 2
	/*
	 * Enumeration is extensible
	 */
} e_CurvatureCalculationMode;

/* CurvatureCalculationMode */
typedef long	 CurvatureCalculationMode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CurvatureCalculationMode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CurvatureCalculationMode;
extern const asn_INTEGER_specifics_t asn_SPC_CurvatureCalculationMode_specs_1;
asn_struct_free_f CurvatureCalculationMode_free;
asn_constr_check_f CurvatureCalculationMode_constraint;
per_type_decoder_f CurvatureCalculationMode_decode_uper;
per_type_encoder_f CurvatureCalculationMode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CurvatureCalculationMode_H_ */
#include <asn_internal.h>
