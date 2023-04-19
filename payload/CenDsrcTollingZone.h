/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include "Latitude.h"
#include "Longitude.h"
#include "CenDsrcTollingZoneID.h"
#include <constr_SEQUENCE.h>
#ifndef	_CenDsrcTollingZone_H_
#define	_CenDsrcTollingZone_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CenDsrcTollingZone */
typedef struct CenDsrcTollingZone {
	Latitude_t	 protectedZoneLatitude;
	Longitude_t	 protectedZoneLongitude;
	CenDsrcTollingZoneID_t	*cenDsrcTollingZoneID;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CenDsrcTollingZone_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CenDsrcTollingZone;
extern asn_SEQUENCE_specifics_t asn_SPC_CenDsrcTollingZone_specs_1;
extern asn_TYPE_member_t asn_MBR_CenDsrcTollingZone_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _CenDsrcTollingZone_H_ */
#include <asn_internal.h>
