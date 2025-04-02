/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_Wgs84AngleValue_H_
#define	_Wgs84AngleValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Wgs84AngleValue {
	Wgs84AngleValue_wgs84North	= 0,
	Wgs84AngleValue_wgs84East	= 900,
	Wgs84AngleValue_wgs84South	= 1800,
	Wgs84AngleValue_wgs84West	= 2700,
	Wgs84AngleValue_doNotUse	= 3600,
	Wgs84AngleValue_unavailable	= 3601
} e_Wgs84AngleValue;

/* Wgs84AngleValue */
typedef long	 Wgs84AngleValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Wgs84AngleValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Wgs84AngleValue;
asn_struct_free_f Wgs84AngleValue_free;
asn_constr_check_f Wgs84AngleValue_constraint;
per_type_decoder_f Wgs84AngleValue_decode_uper;
per_type_encoder_f Wgs84AngleValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Wgs84AngleValue_H_ */
#include <asn_internal.h>
