/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "LanePositionAndType.h"

static int asn_DFL_3_cmp_0(const void *sptr) {
	const LaneType_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_3_set_0(void **sptr) {
	LaneType_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
static int asn_DFL_4_cmp_0(const void *sptr) {
	const Direction_t *st = sptr;
	
	if(!st) {
		return -1; /* No value is not a default value */
	}
	
	/* Test default value 0 */
	return (*st != 0);
}
static int asn_DFL_4_set_0(void **sptr) {
	Direction_t *st = *sptr;
	
	if(!st) {
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	/* Install default value 0 */
	*st = 0;
	return 0;
}
asn_TYPE_member_t asn_MBR_LanePositionAndType_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LanePositionAndType, transversalPosition),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LanePosition,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"transversalPosition"
		},
	{ ATF_NOFLAGS, 2, offsetof(struct LanePositionAndType, laneType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LaneType,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		&asn_DFL_3_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_3_set_0,	/* Set DEFAULT 0 */
		"laneType"
		},
	{ ATF_NOFLAGS, 1, offsetof(struct LanePositionAndType, direction),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Direction,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		&asn_DFL_4_cmp_0,	/* Compare DEFAULT 0 */
		&asn_DFL_4_set_0,	/* Set DEFAULT 0 */
		"direction"
		},
};
static const int asn_MAP_LanePositionAndType_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_LanePositionAndType_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LanePositionAndType_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* transversalPosition */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* laneType */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* direction */
};
asn_SEQUENCE_specifics_t asn_SPC_LanePositionAndType_specs_1 = {
	sizeof(struct LanePositionAndType),
	offsetof(struct LanePositionAndType, _asn_ctx),
	asn_MAP_LanePositionAndType_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_LanePositionAndType_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LanePositionAndType = {
	"LanePositionAndType",
	"LanePositionAndType",
	&asn_OP_SEQUENCE,
	asn_DEF_LanePositionAndType_tags_1,
	sizeof(asn_DEF_LanePositionAndType_tags_1)
		/sizeof(asn_DEF_LanePositionAndType_tags_1[0]), /* 1 */
	asn_DEF_LanePositionAndType_tags_1,	/* Same as above */
	sizeof(asn_DEF_LanePositionAndType_tags_1)
		/sizeof(asn_DEF_LanePositionAndType_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_LanePositionAndType_1,
	3,	/* Elements count */
	&asn_SPC_LanePositionAndType_specs_1	/* Additional specs */
};

