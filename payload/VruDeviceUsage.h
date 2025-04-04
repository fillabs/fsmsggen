/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_VruDeviceUsage_H_
#define	_VruDeviceUsage_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VruDeviceUsage {
	VruDeviceUsage_unavailable	= 0,
	VruDeviceUsage_other	= 1,
	VruDeviceUsage_idle	= 2,
	VruDeviceUsage_listeningToAudio	= 3,
	VruDeviceUsage_typing	= 4,
	VruDeviceUsage_calling	= 5,
	VruDeviceUsage_playingGames	= 6,
	VruDeviceUsage_reading	= 7,
	VruDeviceUsage_viewing	= 8
} e_VruDeviceUsage;

/* VruDeviceUsage */
typedef long	 VruDeviceUsage_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VruDeviceUsage_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VruDeviceUsage;
asn_struct_free_f VruDeviceUsage_free;
asn_constr_check_f VruDeviceUsage_constraint;
per_type_decoder_f VruDeviceUsage_decode_uper;
per_type_encoder_f VruDeviceUsage_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VruDeviceUsage_H_ */
#include <asn_internal.h>
