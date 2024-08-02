/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NULL.h>
#include "TimestampIts.h"
#include <NativeInteger.h>
#include <constr_CHOICE.h>
#ifndef	_ParkingSpaceStatus_H_
#define	_ParkingSpaceStatus_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ParkingSpaceStatus_PR {
	ParkingSpaceStatus_PR_NOTHING,	/* No components present */
	ParkingSpaceStatus_PR_unknown,
	ParkingSpaceStatus_PR_free,
	ParkingSpaceStatus_PR_freeUntil,
	ParkingSpaceStatus_PR_fullyOccupied,
	ParkingSpaceStatus_PR_partiallyOccupied,
	ParkingSpaceStatus_PR_occupiedUntil,
	ParkingSpaceStatus_PR_reservedUntil,
	ParkingSpaceStatus_PR_accessBlocked,
	ParkingSpaceStatus_PR_retrictedUsage
	/* Extensions may appear below */
	
} ParkingSpaceStatus_PR;

/* ParkingSpaceStatus */
typedef struct ParkingSpaceStatus {
	ParkingSpaceStatus_PR present;
	union ParkingSpaceStatus_u {
		NULL_t	 unknown;
		NULL_t	 free;
		TimestampIts_t	 freeUntil;
		NULL_t	 fullyOccupied;
		long	 partiallyOccupied;
		TimestampIts_t	 occupiedUntil;
		TimestampIts_t	 reservedUntil;
		NULL_t	 accessBlocked;
		NULL_t	 retrictedUsage;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ParkingSpaceStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ParkingSpaceStatus;
extern asn_CHOICE_specifics_t asn_SPC_ParkingSpaceStatus_specs_1;
extern asn_TYPE_member_t asn_MBR_ParkingSpaceStatus_1[9];
extern asn_per_constraints_t asn_PER_type_ParkingSpaceStatus_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ParkingSpaceStatus_H_ */
#include <asn_internal.h>
