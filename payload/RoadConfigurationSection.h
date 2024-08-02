/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "RoadSectionDefinition.h"
#include "RoadType.h"
#include <constr_SEQUENCE.h>
#ifndef	_RoadConfigurationSection_H_
#define	_RoadConfigurationSection_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct BasicLaneConfiguration;
struct MapemConfiguration;

/* RoadConfigurationSection */
typedef struct RoadConfigurationSection {
	RoadSectionDefinition_t	 roadSectionDefinition;
	RoadType_t	*roadType;	/* OPTIONAL */
	struct BasicLaneConfiguration	*laneConfiguration;	/* OPTIONAL */
	struct MapemConfiguration	*mapemConfiguration;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RoadConfigurationSection_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RoadConfigurationSection;
extern asn_SEQUENCE_specifics_t asn_SPC_RoadConfigurationSection_specs_1;
extern asn_TYPE_member_t asn_MBR_RoadConfigurationSection_1[4];
extern asn_per_constraints_t asn_PER_type_RoadConfigurationSection_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "BasicLaneConfiguration.h"
#include "MapemConfiguration.h"

#endif	/* _RoadConfigurationSection_H_ */
#include <asn_internal.h>
