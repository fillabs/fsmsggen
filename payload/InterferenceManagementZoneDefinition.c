/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "InterferenceManagementZoneDefinition.h"

static int
memb_interferenceManagementZoneShape_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_PER_memb_interferenceManagementZoneShape_constr_5 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  3,  3,  0,  5 }	/* (0..5,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_member_t asn_MBR_InterferenceManagementZoneDefinition_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct InterferenceManagementZoneDefinition, interferenceManagementZoneLatitude),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Latitude,
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
		"interferenceManagementZoneLatitude"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterferenceManagementZoneDefinition, interferenceManagementZoneLongitude),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Longitude,
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
		"interferenceManagementZoneLongitude"
		},
	{ ATF_POINTER, 2, offsetof(struct InterferenceManagementZoneDefinition, interferenceManagementZoneId),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtectedZoneId,
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
		"interferenceManagementZoneId"
		},
	{ ATF_POINTER, 1, offsetof(struct InterferenceManagementZoneDefinition, interferenceManagementZoneShape),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Shape,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			&asn_PER_memb_interferenceManagementZoneShape_constr_5,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			memb_interferenceManagementZoneShape_constraint_1
		},
		0, 0, /* No default value */
		"interferenceManagementZoneShape"
		},
};
static const int asn_MAP_InterferenceManagementZoneDefinition_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_InterferenceManagementZoneDefinition_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterferenceManagementZoneDefinition_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interferenceManagementZoneLatitude */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* interferenceManagementZoneLongitude */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* interferenceManagementZoneId */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* interferenceManagementZoneShape */
};
asn_SEQUENCE_specifics_t asn_SPC_InterferenceManagementZoneDefinition_specs_1 = {
	sizeof(struct InterferenceManagementZoneDefinition),
	offsetof(struct InterferenceManagementZoneDefinition, _asn_ctx),
	asn_MAP_InterferenceManagementZoneDefinition_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_InterferenceManagementZoneDefinition_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterferenceManagementZoneDefinition = {
	"InterferenceManagementZoneDefinition",
	"InterferenceManagementZoneDefinition",
	&asn_OP_SEQUENCE,
	asn_DEF_InterferenceManagementZoneDefinition_tags_1,
	sizeof(asn_DEF_InterferenceManagementZoneDefinition_tags_1)
		/sizeof(asn_DEF_InterferenceManagementZoneDefinition_tags_1[0]), /* 1 */
	asn_DEF_InterferenceManagementZoneDefinition_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterferenceManagementZoneDefinition_tags_1)
		/sizeof(asn_DEF_InterferenceManagementZoneDefinition_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_InterferenceManagementZoneDefinition_1,
	4,	/* Elements count */
	&asn_SPC_InterferenceManagementZoneDefinition_specs_1	/* Additional specs */
};

