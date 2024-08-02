/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_CorrelationCellValue_H_
#define	_CorrelationCellValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CorrelationCellValue {
	CorrelationCellValue_full_negative_correlation	= -100,
	CorrelationCellValue_no_correlation	= 0,
	CorrelationCellValue_full_positive_correlation	= 100,
	CorrelationCellValue_unavailable	= 101
} e_CorrelationCellValue;

/* CorrelationCellValue */
typedef long	 CorrelationCellValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CorrelationCellValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CorrelationCellValue;
asn_struct_free_f CorrelationCellValue_free;
asn_constr_check_f CorrelationCellValue_constraint;
ber_type_decoder_f CorrelationCellValue_decode_ber;
der_type_encoder_f CorrelationCellValue_encode_der;
per_type_decoder_f CorrelationCellValue_decode_uper;
per_type_encoder_f CorrelationCellValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CorrelationCellValue_H_ */
#include <asn_internal.h>
