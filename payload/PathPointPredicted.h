/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "DeltaLatitude.h"
#include "DeltaLongitude.h"
#include "DeltaAltitude.h"
#include "AltitudeConfidence.h"
#include "StandardLength9b.h"
#include <constr_SEQUENCE.h>
#ifndef	_PathPointPredicted_H_
#define	_PathPointPredicted_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PosConfidenceEllipse;
struct PathDeltaTimeChoice;

/* PathPointPredicted */
typedef struct PathPointPredicted {
	DeltaLatitude_t	 deltaLatitude;
	DeltaLongitude_t	 deltaLongitude;
	struct PosConfidenceEllipse	*horizontalPositionConfidence;	/* OPTIONAL */
	DeltaAltitude_t	*deltaAltitude;	/* DEFAULT 12800 */
	AltitudeConfidence_t	*altitudeConfidence;	/* DEFAULT 15 */
	struct PathDeltaTimeChoice	*pathDeltaTime;	/* OPTIONAL */
	StandardLength9b_t	*symmetricAreaOffset;	/* OPTIONAL */
	StandardLength9b_t	*asymmetricAreaOffset;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PathPointPredicted_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PathPointPredicted;
extern asn_SEQUENCE_specifics_t asn_SPC_PathPointPredicted_specs_1;
extern asn_TYPE_member_t asn_MBR_PathPointPredicted_1[8];
extern asn_per_constraints_t asn_PER_type_PathPointPredicted_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PosConfidenceEllipse.h"
#include "PathDeltaTimeChoice.h"

#endif	/* _PathPointPredicted_H_ */
#include <asn_internal.h>
