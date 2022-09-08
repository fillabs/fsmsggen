/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <UTF8String.h>
#ifndef	_OpeningDaysHours_H_
#define	_OpeningDaysHours_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* OpeningDaysHours */
typedef UTF8String_t	 OpeningDaysHours_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OpeningDaysHours;
asn_struct_free_f OpeningDaysHours_free;
asn_struct_print_f OpeningDaysHours_print;
asn_constr_check_f OpeningDaysHours_constraint;
ber_type_decoder_f OpeningDaysHours_decode_ber;
der_type_encoder_f OpeningDaysHours_encode_der;
per_type_decoder_f OpeningDaysHours_decode_uper;
per_type_encoder_f OpeningDaysHours_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _OpeningDaysHours_H_ */
#include <asn_internal.h>
