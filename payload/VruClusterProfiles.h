/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <BIT_STRING.h>
#ifndef	_VruClusterProfiles_H_
#define	_VruClusterProfiles_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VruClusterProfiles {
	VruClusterProfiles_pedestrian	= 0,
	VruClusterProfiles_bicyclist	= 1,
	VruClusterProfiles_motorcyclist	= 2,
	VruClusterProfiles_animal	= 3
} e_VruClusterProfiles;

/* VruClusterProfiles */
typedef BIT_STRING_t	 VruClusterProfiles_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VruClusterProfiles_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VruClusterProfiles;
asn_struct_free_f VruClusterProfiles_free;
asn_constr_check_f VruClusterProfiles_constraint;
per_type_decoder_f VruClusterProfiles_decode_uper;
per_type_encoder_f VruClusterProfiles_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VruClusterProfiles_H_ */
#include <asn_internal.h>
