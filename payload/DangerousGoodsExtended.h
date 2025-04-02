/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "DangerousGoodsBasic.h"
#include <NativeInteger.h>
#include <BOOLEAN.h>
#include <IA5String.h>
#include "PhoneNumber.h"
#include <UTF8String.h>
#include <constr_SEQUENCE.h>
#ifndef	_DangerousGoodsExtended_H_
#define	_DangerousGoodsExtended_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DangerousGoodsExtended */
typedef struct DangerousGoodsExtended {
	DangerousGoodsBasic_t	 dangerousGoodsType;
	long	 unNumber;
	BOOLEAN_t	 elevatedTemperature;
	BOOLEAN_t	 tunnelsRestricted;
	BOOLEAN_t	 limitedQuantity;
	IA5String_t	*emergencyActionCode;	/* OPTIONAL */
	PhoneNumber_t	*phoneNumber;	/* OPTIONAL */
	UTF8String_t	*companyName;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DangerousGoodsExtended_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DangerousGoodsExtended;
extern asn_SEQUENCE_specifics_t asn_SPC_DangerousGoodsExtended_specs_1;
extern asn_TYPE_member_t asn_MBR_DangerousGoodsExtended_1[8];

#ifdef __cplusplus
}
#endif

#endif	/* _DangerousGoodsExtended_H_ */
#include <asn_internal.h>
