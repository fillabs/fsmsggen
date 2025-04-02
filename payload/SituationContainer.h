/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/DENM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "InformationQuality.h"
#include "CauseCodeV2.h"
#include "Position1d.h"
#include <constr_SEQUENCE.h>
#ifndef	_SituationContainer_H_
#define	_SituationContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CauseCodeV2;
struct EventZone;
struct ActionIdList;

/* SituationContainer */
typedef struct SituationContainer {
	InformationQuality_t	 informationQuality;
	CauseCodeV2_t	 eventType;
	struct CauseCodeV2	*linkedCause;	/* OPTIONAL */
	struct EventZone	*eventZone;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct SituationContainer__ext1 {
		struct ActionIdList	*linkedDenms;	/* OPTIONAL */
		Position1d_t	*eventEnd;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SituationContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SituationContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_SituationContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_SituationContainer_1[5];
extern asn_per_constraints_t asn_PER_type_SituationContainer_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CauseCodeV2.h"
#include "EventZone.h"
#include "ActionIdList.h"

#endif	/* _SituationContainer_H_ */
#include <asn_internal.h>
