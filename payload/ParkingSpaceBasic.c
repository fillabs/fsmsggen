/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "ParkingSpaceBasic.h"

asn_TYPE_member_t asn_MBR_ParkingSpaceBasic_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ParkingSpaceBasic, id),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Identifier2B,
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
		"id"
		},
	{ ATF_POINTER, 1, offsetof(struct ParkingSpaceBasic, location),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DeltaReferencePosition,
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
		"location"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ParkingSpaceBasic, status),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ParkingSpaceStatus,
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
		"status"
		},
};
static const int asn_MAP_ParkingSpaceBasic_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_ParkingSpaceBasic_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ParkingSpaceBasic_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* id */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* location */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* status */
};
asn_SEQUENCE_specifics_t asn_SPC_ParkingSpaceBasic_specs_1 = {
	sizeof(struct ParkingSpaceBasic),
	offsetof(struct ParkingSpaceBasic, _asn_ctx),
	asn_MAP_ParkingSpaceBasic_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_ParkingSpaceBasic_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_ParkingSpaceBasic = {
	"ParkingSpaceBasic",
	"ParkingSpaceBasic",
	&asn_OP_SEQUENCE,
	asn_DEF_ParkingSpaceBasic_tags_1,
	sizeof(asn_DEF_ParkingSpaceBasic_tags_1)
		/sizeof(asn_DEF_ParkingSpaceBasic_tags_1[0]), /* 1 */
	asn_DEF_ParkingSpaceBasic_tags_1,	/* Same as above */
	sizeof(asn_DEF_ParkingSpaceBasic_tags_1)
		/sizeof(asn_DEF_ParkingSpaceBasic_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_ParkingSpaceBasic_1,
	3,	/* Elements count */
	&asn_SPC_ParkingSpaceBasic_specs_1	/* Additional specs */
};
