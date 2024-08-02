/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_Wgs84AngleConfidence_H_
#define	_Wgs84AngleConfidence_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Wgs84AngleConfidence {
	Wgs84AngleConfidence_outOfRange	= 126,
	Wgs84AngleConfidence_unavailable	= 127
} e_Wgs84AngleConfidence;

/* Wgs84AngleConfidence */
typedef long	 Wgs84AngleConfidence_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Wgs84AngleConfidence_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Wgs84AngleConfidence;
asn_struct_free_f Wgs84AngleConfidence_free;
asn_constr_check_f Wgs84AngleConfidence_constraint;
ber_type_decoder_f Wgs84AngleConfidence_decode_ber;
der_type_encoder_f Wgs84AngleConfidence_encode_der;
per_type_decoder_f Wgs84AngleConfidence_decode_uper;
per_type_encoder_f Wgs84AngleConfidence_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Wgs84AngleConfidence_H_ */
#include <asn_internal.h>