/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_Temperature_H_
#define	_Temperature_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Temperature {
	Temperature_equalOrSmallerThanMinus60Deg	= -60,
	Temperature_oneDegreeCelsius	= 1,
	Temperature_equalOrGreaterThan67Deg	= 67
} e_Temperature;

/* Temperature */
typedef long	 Temperature_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Temperature_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Temperature;
asn_struct_free_f Temperature_free;
asn_struct_print_f Temperature_print;
asn_constr_check_f Temperature_constraint;
ber_type_decoder_f Temperature_decode_ber;
der_type_encoder_f Temperature_encode_der;
per_type_decoder_f Temperature_decode_uper;
per_type_encoder_f Temperature_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Temperature_H_ */
#include <asn_internal.h>
