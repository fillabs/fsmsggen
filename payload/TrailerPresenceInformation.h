/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_TrailerPresenceInformation_H_
#define	_TrailerPresenceInformation_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TrailerPresenceInformation {
	TrailerPresenceInformation_noTrailerPresent	= 0,
	TrailerPresenceInformation_trailerPresentWithKnownLength	= 1,
	TrailerPresenceInformation_trailerPresentWithUnknownLength	= 2,
	TrailerPresenceInformation_trailerPresenceIsUnknown	= 3,
	TrailerPresenceInformation_unavailable	= 4
} e_TrailerPresenceInformation;

/* TrailerPresenceInformation */
typedef long	 TrailerPresenceInformation_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TrailerPresenceInformation_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TrailerPresenceInformation;
extern const asn_INTEGER_specifics_t asn_SPC_TrailerPresenceInformation_specs_1;
asn_struct_free_f TrailerPresenceInformation_free;
asn_constr_check_f TrailerPresenceInformation_constraint;
per_type_decoder_f TrailerPresenceInformation_decode_uper;
per_type_encoder_f TrailerPresenceInformation_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TrailerPresenceInformation_H_ */
#include <asn_internal.h>
