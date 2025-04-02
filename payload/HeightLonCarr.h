/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_HeightLonCarr_H_
#define	_HeightLonCarr_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HeightLonCarr {
	HeightLonCarr_outOfRange	= 99,
	HeightLonCarr_unavailable	= 100
} e_HeightLonCarr;

/* HeightLonCarr */
typedef long	 HeightLonCarr_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_HeightLonCarr_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_HeightLonCarr;
asn_struct_free_f HeightLonCarr_free;
asn_constr_check_f HeightLonCarr_constraint;
per_type_decoder_f HeightLonCarr_decode_uper;
per_type_encoder_f HeightLonCarr_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _HeightLonCarr_H_ */
#include <asn_internal.h>
