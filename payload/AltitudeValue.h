/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_AltitudeValue_H_
#define	_AltitudeValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AltitudeValue {
	AltitudeValue_negativeOutOfRange	= -100000,
	AltitudeValue_postiveOutOfRange	= 800000,
	AltitudeValue_unavailable	= 800001
} e_AltitudeValue;

/* AltitudeValue */
typedef long	 AltitudeValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AltitudeValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AltitudeValue;
asn_struct_free_f AltitudeValue_free;
asn_constr_check_f AltitudeValue_constraint;
per_type_decoder_f AltitudeValue_decode_uper;
per_type_encoder_f AltitudeValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AltitudeValue_H_ */
#include <asn_internal.h>
