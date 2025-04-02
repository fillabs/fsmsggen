/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_CurvatureConfidence_H_
#define	_CurvatureConfidence_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CurvatureConfidence {
	CurvatureConfidence_onePerMeter_0_00002	= 0,
	CurvatureConfidence_onePerMeter_0_0001	= 1,
	CurvatureConfidence_onePerMeter_0_0005	= 2,
	CurvatureConfidence_onePerMeter_0_002	= 3,
	CurvatureConfidence_onePerMeter_0_01	= 4,
	CurvatureConfidence_onePerMeter_0_1	= 5,
	CurvatureConfidence_outOfRange	= 6,
	CurvatureConfidence_unavailable	= 7
} e_CurvatureConfidence;

/* CurvatureConfidence */
typedef long	 CurvatureConfidence_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CurvatureConfidence_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CurvatureConfidence;
extern const asn_INTEGER_specifics_t asn_SPC_CurvatureConfidence_specs_1;
asn_struct_free_f CurvatureConfidence_free;
asn_constr_check_f CurvatureConfidence_constraint;
per_type_decoder_f CurvatureConfidence_decode_uper;
per_type_encoder_f CurvatureConfidence_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CurvatureConfidence_H_ */
#include <asn_internal.h>
