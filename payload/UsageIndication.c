/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "UsageIndication.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_UsageIndication_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  2,  2,  0,  2 }	/* (0..2,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_UsageIndication_value2enum_1[] = {
	{ 0,	12,	"noIndication" },
	{ 1,	10,	"specialUse" },
	{ 2,	15,	"rescueOperation" },
	{ 3,	8,	"railroad" },
	{ 4,	10,	"fixedRoute" },
	{ 5,	15,	"restrictedRoute" },
	{ 6,	6,	"adasAd" },
	{ 7,	10,	"navigation" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_UsageIndication_enum2value_1[] = {
	6,	/* adasAd(6) */
	4,	/* fixedRoute(4) */
	7,	/* navigation(7) */
	0,	/* noIndication(0) */
	3,	/* railroad(3) */
	2,	/* rescueOperation(2) */
	5,	/* restrictedRoute(5) */
	1	/* specialUse(1) */
	/* This list is extensible */
};
const asn_INTEGER_specifics_t asn_SPC_UsageIndication_specs_1 = {
	asn_MAP_UsageIndication_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_UsageIndication_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	4,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_UsageIndication_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_UsageIndication = {
	"UsageIndication",
	"UsageIndication",
	&asn_OP_NativeEnumerated,
	asn_DEF_UsageIndication_tags_1,
	sizeof(asn_DEF_UsageIndication_tags_1)
		/sizeof(asn_DEF_UsageIndication_tags_1[0]), /* 1 */
	asn_DEF_UsageIndication_tags_1,	/* Same as above */
	sizeof(asn_DEF_UsageIndication_tags_1)
		/sizeof(asn_DEF_UsageIndication_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_UsageIndication_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_UsageIndication_specs_1	/* Additional specs */
};

