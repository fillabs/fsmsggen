/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <BIT_STRING.h>
#ifndef	_StoredInformationType_H_
#define	_StoredInformationType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum StoredInformationType {
	StoredInformationType_undefined	= 0,
	StoredInformationType_staticDb	= 1,
	StoredInformationType_dynamicDb	= 2,
	StoredInformationType_realTimeDb	= 3,
	StoredInformationType_map	= 4
} e_StoredInformationType;

/* StoredInformationType */
typedef BIT_STRING_t	 StoredInformationType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_StoredInformationType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_StoredInformationType;
asn_struct_free_f StoredInformationType_free;
asn_constr_check_f StoredInformationType_constraint;
per_type_decoder_f StoredInformationType_decode_uper;
per_type_encoder_f StoredInformationType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _StoredInformationType_H_ */
#include <asn_internal.h>
