/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_SensorType_H_
#define	_SensorType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SensorType {
	SensorType_undefined	= 0,
	SensorType_radar	= 1,
	SensorType_lidar	= 2,
	SensorType_monovideo	= 3,
	SensorType_stereovision	= 4,
	SensorType_nightvision	= 5,
	SensorType_ultrasonic	= 6,
	SensorType_pmd	= 7,
	SensorType_inductionLoop	= 8,
	SensorType_sphericalCamera	= 9,
	SensorType_uwb	= 10,
	SensorType_acoustic	= 11,
	SensorType_localAggregation	= 12,
	SensorType_itsAggregation	= 13,
	SensorType_rfid	= 14
} e_SensorType;

/* SensorType */
typedef long	 SensorType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SensorType;
asn_struct_free_f SensorType_free;
asn_constr_check_f SensorType_constraint;
ber_type_decoder_f SensorType_decode_ber;
der_type_encoder_f SensorType_encode_der;
per_type_decoder_f SensorType_decode_uper;
per_type_encoder_f SensorType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _SensorType_H_ */
#include <asn_internal.h>