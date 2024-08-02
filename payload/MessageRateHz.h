/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#ifndef	_MessageRateHz_H_
#define	_MessageRateHz_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MessageRateHz */
typedef struct MessageRateHz {
	long	 mantissa;
	long	 exponent;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MessageRateHz_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MessageRateHz;

#ifdef __cplusplus
}
#endif

#endif	/* _MessageRateHz_H_ */
#include <asn_internal.h>
