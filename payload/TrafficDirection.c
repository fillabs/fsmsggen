/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "TrafficDirection.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_TrafficDirection_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  3 }	/* (0..3) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_TrafficDirection_value2enum_1[] = {
	{ 0,	20,	"allTrafficDirections" },
	{ 1,	52,	"sameAsReferenceDirection-upstreamOfReferencePosition" },
	{ 2,	54,	"sameAsReferenceDirection-downstreamOfReferencePosition" },
	{ 3,	28,	"oppositeToReferenceDirection" }
};
static const unsigned int asn_MAP_TrafficDirection_enum2value_1[] = {
	0,	/* allTrafficDirections(0) */
	3,	/* oppositeToReferenceDirection(3) */
	2,	/* sameAsReferenceDirection-downstreamOfReferencePosition(2) */
	1	/* sameAsReferenceDirection-upstreamOfReferencePosition(1) */
};
const asn_INTEGER_specifics_t asn_SPC_TrafficDirection_specs_1 = {
	asn_MAP_TrafficDirection_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_TrafficDirection_enum2value_1,	/* N => "tag"; sorted by N */
	4,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_TrafficDirection_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_TrafficDirection = {
	"TrafficDirection",
	"TrafficDirection",
	&asn_OP_NativeEnumerated,
	asn_DEF_TrafficDirection_tags_1,
	sizeof(asn_DEF_TrafficDirection_tags_1)
		/sizeof(asn_DEF_TrafficDirection_tags_1[0]), /* 1 */
	asn_DEF_TrafficDirection_tags_1,	/* Same as above */
	sizeof(asn_DEF_TrafficDirection_tags_1)
		/sizeof(asn_DEF_TrafficDirection_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_TrafficDirection_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_TrafficDirection_specs_1	/* Additional specs */
};

