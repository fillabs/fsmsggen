/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "ObjectFace.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_ObjectFace_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  5 }	/* (0..5) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_ObjectFace_value2enum_1[] = {
	{ 0,	5,	"front" },
	{ 1,	13,	"sideLeftFront" },
	{ 2,	12,	"sideLeftBack" },
	{ 3,	14,	"sideRightFront" },
	{ 4,	13,	"sideRightBack" },
	{ 5,	4,	"back" }
};
static const unsigned int asn_MAP_ObjectFace_enum2value_1[] = {
	5,	/* back(5) */
	0,	/* front(0) */
	2,	/* sideLeftBack(2) */
	1,	/* sideLeftFront(1) */
	4,	/* sideRightBack(4) */
	3	/* sideRightFront(3) */
};
const asn_INTEGER_specifics_t asn_SPC_ObjectFace_specs_1 = {
	asn_MAP_ObjectFace_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_ObjectFace_enum2value_1,	/* N => "tag"; sorted by N */
	6,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_ObjectFace_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_ObjectFace = {
	"ObjectFace",
	"ObjectFace",
	&asn_OP_NativeEnumerated,
	asn_DEF_ObjectFace_tags_1,
	sizeof(asn_DEF_ObjectFace_tags_1)
		/sizeof(asn_DEF_ObjectFace_tags_1[0]), /* 1 */
	asn_DEF_ObjectFace_tags_1,	/* Same as above */
	sizeof(asn_DEF_ObjectFace_tags_1)
		/sizeof(asn_DEF_ObjectFace_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_ObjectFace_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_ObjectFace_specs_1	/* Additional specs */
};

