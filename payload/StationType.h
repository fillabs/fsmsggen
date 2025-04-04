/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_StationType_H_
#define	_StationType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum StationType {
	StationType_unknown	= 0,
	StationType_pedestrian	= 1,
	StationType_cyclist	= 2,
	StationType_moped	= 3,
	StationType_motorcycle	= 4,
	StationType_passengerCar	= 5,
	StationType_bus	= 6,
	StationType_lightTruck	= 7,
	StationType_heavyTruck	= 8,
	StationType_trailer	= 9,
	StationType_specialVehicle	= 10,
	StationType_tram	= 11,
	StationType_lightVruVehicle	= 12,
	StationType_animal	= 13,
	StationType_roadSideUnit	= 15
} e_StationType;

/* StationType */
typedef long	 StationType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_StationType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_StationType;
asn_struct_free_f StationType_free;
asn_constr_check_f StationType_constraint;
per_type_decoder_f StationType_decode_uper;
per_type_encoder_f StationType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _StationType_H_ */
#include <asn_internal.h>
