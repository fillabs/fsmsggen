/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_TrafficParticipantType_H_
#define	_TrafficParticipantType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TrafficParticipantType {
	TrafficParticipantType_unknown	= 0,
	TrafficParticipantType_pedestrian	= 1,
	TrafficParticipantType_cyclist	= 2,
	TrafficParticipantType_moped	= 3,
	TrafficParticipantType_motorcycle	= 4,
	TrafficParticipantType_passengerCar	= 5,
	TrafficParticipantType_bus	= 6,
	TrafficParticipantType_lightTruck	= 7,
	TrafficParticipantType_heavyTruck	= 8,
	TrafficParticipantType_trailer	= 9,
	TrafficParticipantType_specialVehicle	= 10,
	TrafficParticipantType_tram	= 11,
	TrafficParticipantType_lightVruVehicle	= 12,
	TrafficParticipantType_animal	= 13,
	TrafficParticipantType_agricultural	= 14,
	TrafficParticipantType_roadSideUnit	= 15
} e_TrafficParticipantType;

/* TrafficParticipantType */
typedef long	 TrafficParticipantType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TrafficParticipantType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TrafficParticipantType;
asn_struct_free_f TrafficParticipantType_free;
asn_constr_check_f TrafficParticipantType_constraint;
ber_type_decoder_f TrafficParticipantType_decode_ber;
der_type_encoder_f TrafficParticipantType_encode_der;
per_type_decoder_f TrafficParticipantType_decode_uper;
per_type_encoder_f TrafficParticipantType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TrafficParticipantType_H_ */
#include <asn_internal.h>
