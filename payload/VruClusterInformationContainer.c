/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "VAM-PDU-Descriptions"
 * 	found in "asn1/VAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "VruClusterInformationContainer.h"

static int
memb_vruClusterInformation_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
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
static asn_per_constraints_t asn_PER_memb_vruClusterInformation_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_member_t asn_MBR_VruClusterInformationContainer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct VruClusterInformationContainer, vruClusterInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_VruClusterInformation,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			&asn_PER_memb_vruClusterInformation_constr_2,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			memb_vruClusterInformation_constraint_1
		},
		0, 0, /* No default value */
		"vruClusterInformation"
		},
};
static const ber_tlv_tag_t asn_DEF_VruClusterInformationContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_VruClusterInformationContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* vruClusterInformation */
};
asn_SEQUENCE_specifics_t asn_SPC_VruClusterInformationContainer_specs_1 = {
	sizeof(struct VruClusterInformationContainer),
	offsetof(struct VruClusterInformationContainer, _asn_ctx),
	asn_MAP_VruClusterInformationContainer_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_VruClusterInformationContainer = {
	"VruClusterInformationContainer",
	"VruClusterInformationContainer",
	&asn_OP_SEQUENCE,
	asn_DEF_VruClusterInformationContainer_tags_1,
	sizeof(asn_DEF_VruClusterInformationContainer_tags_1)
		/sizeof(asn_DEF_VruClusterInformationContainer_tags_1[0]), /* 1 */
	asn_DEF_VruClusterInformationContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_VruClusterInformationContainer_tags_1)
		/sizeof(asn_DEF_VruClusterInformationContainer_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_VruClusterInformationContainer_1,
	1,	/* Elements count */
	&asn_SPC_VruClusterInformationContainer_specs_1	/* Additional specs */
};

