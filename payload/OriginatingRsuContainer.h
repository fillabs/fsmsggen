/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-OriginatingStationContainers"
 * 	found in "asn1/CPM-OriginatingStationContainers.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <constr_SEQUENCE.h>
#ifndef	_OriginatingRsuContainer_H_
#define	_OriginatingRsuContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MapReference;

/* OriginatingRsuContainer */
typedef struct OriginatingRsuContainer {
	struct MapReference	*mapReference;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OriginatingRsuContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OriginatingRsuContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_OriginatingRsuContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_OriginatingRsuContainer_1[1];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MapReference.h"

#endif	/* _OriginatingRsuContainer_H_ */
#include <asn_internal.h>