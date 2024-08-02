/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "AngularAccelerationConfidence.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_AngularAccelerationConfidence_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 3,  3,  0,  7 }	/* (0..7) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_AngularAccelerationConfidence_value2enum_1[] = {
	{ 0,	16,	"degSecSquared-01" },
	{ 1,	16,	"degSecSquared-02" },
	{ 2,	16,	"degSecSquared-05" },
	{ 3,	16,	"degSecSquared-10" },
	{ 4,	16,	"degSecSquared-20" },
	{ 5,	16,	"degSecSquared-50" },
	{ 6,	10,	"outOfRange" },
	{ 7,	11,	"unavailable" }
};
static const unsigned int asn_MAP_AngularAccelerationConfidence_enum2value_1[] = {
	0,	/* degSecSquared-01(0) */
	1,	/* degSecSquared-02(1) */
	2,	/* degSecSquared-05(2) */
	3,	/* degSecSquared-10(3) */
	4,	/* degSecSquared-20(4) */
	5,	/* degSecSquared-50(5) */
	6,	/* outOfRange(6) */
	7	/* unavailable(7) */
};
const asn_INTEGER_specifics_t asn_SPC_AngularAccelerationConfidence_specs_1 = {
	asn_MAP_AngularAccelerationConfidence_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_AngularAccelerationConfidence_enum2value_1,	/* N => "tag"; sorted by N */
	8,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_AngularAccelerationConfidence_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_AngularAccelerationConfidence = {
	"AngularAccelerationConfidence",
	"AngularAccelerationConfidence",
	&asn_OP_NativeEnumerated,
	asn_DEF_AngularAccelerationConfidence_tags_1,
	sizeof(asn_DEF_AngularAccelerationConfidence_tags_1)
		/sizeof(asn_DEF_AngularAccelerationConfidence_tags_1[0]), /* 1 */
	asn_DEF_AngularAccelerationConfidence_tags_1,	/* Same as above */
	sizeof(asn_DEF_AngularAccelerationConfidence_tags_1)
		/sizeof(asn_DEF_AngularAccelerationConfidence_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_AngularAccelerationConfidence_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_AngularAccelerationConfidence_specs_1	/* Additional specs */
};

