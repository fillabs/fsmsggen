/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_CauseCodeType_H_
#define	_CauseCodeType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CauseCodeType {
	CauseCodeType_trafficCondition	= 1,
	CauseCodeType_accident	= 2,
	CauseCodeType_roadworks	= 3,
	CauseCodeType_impassability	= 5,
	CauseCodeType_adverseWeatherCondition_Adhesion	= 6,
	CauseCodeType_aquaplaning	= 7,
	CauseCodeType_hazardousLocation_SurfaceCondition	= 9,
	CauseCodeType_hazardousLocation_ObstacleOnTheRoad	= 10,
	CauseCodeType_hazardousLocation_AnimalOnTheRoad	= 11,
	CauseCodeType_humanPresenceOnTheRoad	= 12,
	CauseCodeType_wrongWayDriving	= 14,
	CauseCodeType_rescueAndRecoveryWorkInProgress	= 15,
	CauseCodeType_adverseWeatherCondition_ExtremeWeatherCondition	= 17,
	CauseCodeType_adverseWeatherCondition_Visibility	= 18,
	CauseCodeType_adverseWeatherCondition_Precipitation	= 19,
	CauseCodeType_violence	= 20,
	CauseCodeType_slowVehicle	= 26,
	CauseCodeType_dangerousEndOfQueue	= 27,
	CauseCodeType_publicTransportVehicleApproaching	= 28,
	CauseCodeType_vehicleBreakdown	= 91,
	CauseCodeType_postCrash	= 92,
	CauseCodeType_humanProblem	= 93,
	CauseCodeType_stationaryVehicle	= 94,
	CauseCodeType_emergencyVehicleApproaching	= 95,
	CauseCodeType_hazardousLocation_DangerousCurve	= 96,
	CauseCodeType_collisionRisk	= 97,
	CauseCodeType_signalViolation	= 98,
	CauseCodeType_dangerousSituation	= 99,
	CauseCodeType_railwayLevelCrossing	= 100
} e_CauseCodeType;

/* CauseCodeType */
typedef long	 CauseCodeType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CauseCodeType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CauseCodeType;
asn_struct_free_f CauseCodeType_free;
asn_constr_check_f CauseCodeType_constraint;
per_type_decoder_f CauseCodeType_decode_uper;
per_type_encoder_f CauseCodeType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _CauseCodeType_H_ */
#include <asn_internal.h>
