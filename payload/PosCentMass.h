/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_PosCentMass_H_
#define	_PosCentMass_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PosCentMass {
	PosCentMass_tenCentimetres	= 1,
	PosCentMass_outOfRange	= 62,
	PosCentMass_unavailable	= 63
} e_PosCentMass;

/* PosCentMass */
typedef long	 PosCentMass_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PosCentMass_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PosCentMass;
asn_struct_free_f PosCentMass_free;
asn_constr_check_f PosCentMass_constraint;
per_type_decoder_f PosCentMass_decode_uper;
per_type_encoder_f PosCentMass_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PosCentMass_H_ */
#include <asn_internal.h>
