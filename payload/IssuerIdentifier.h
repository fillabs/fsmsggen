/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_IssuerIdentifier_H_
#define	_IssuerIdentifier_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IssuerIdentifier */
typedef long	 IssuerIdentifier_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_IssuerIdentifier_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_IssuerIdentifier;
asn_struct_free_f IssuerIdentifier_free;
asn_constr_check_f IssuerIdentifier_constraint;
ber_type_decoder_f IssuerIdentifier_decode_ber;
der_type_encoder_f IssuerIdentifier_encode_der;
per_type_decoder_f IssuerIdentifier_decode_uper;
per_type_encoder_f IssuerIdentifier_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _IssuerIdentifier_H_ */
#include <asn_internal.h>
