/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "RequestResponseIndication.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_RequestResponseIndication_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 1,  1,  0,  1 }	/* (0..1) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_RequestResponseIndication_value2enum_1[] = {
	{ 0,	7,	"request" },
	{ 1,	8,	"response" }
};
static const unsigned int asn_MAP_RequestResponseIndication_enum2value_1[] = {
	0,	/* request(0) */
	1	/* response(1) */
};
const asn_INTEGER_specifics_t asn_SPC_RequestResponseIndication_specs_1 = {
	asn_MAP_RequestResponseIndication_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_RequestResponseIndication_enum2value_1,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_RequestResponseIndication_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_RequestResponseIndication = {
	"RequestResponseIndication",
	"RequestResponseIndication",
	&asn_OP_NativeEnumerated,
	asn_DEF_RequestResponseIndication_tags_1,
	sizeof(asn_DEF_RequestResponseIndication_tags_1)
		/sizeof(asn_DEF_RequestResponseIndication_tags_1[0]), /* 1 */
	asn_DEF_RequestResponseIndication_tags_1,	/* Same as above */
	sizeof(asn_DEF_RequestResponseIndication_tags_1)
		/sizeof(asn_DEF_RequestResponseIndication_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_RequestResponseIndication_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_RequestResponseIndication_specs_1	/* Additional specs */
};

