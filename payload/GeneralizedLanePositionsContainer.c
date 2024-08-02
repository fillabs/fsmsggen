/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "GeneralizedLanePositionsContainer.h"

int
GeneralizedLanePositionsContainer_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 4)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using GeneralizedLanePositions,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_GeneralizedLanePositionsContainer_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 2,  2,  1,  4 }	/* (SIZE(1..4)) */,
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const ber_tlv_tag_t asn_DEF_GeneralizedLanePositionsContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_GeneralizedLanePositionsContainer = {
	"GeneralizedLanePositionsContainer",
	"GeneralizedLanePositionsContainer",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_GeneralizedLanePositionsContainer_tags_1,
	sizeof(asn_DEF_GeneralizedLanePositionsContainer_tags_1)
		/sizeof(asn_DEF_GeneralizedLanePositionsContainer_tags_1[0]), /* 1 */
	asn_DEF_GeneralizedLanePositionsContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_GeneralizedLanePositionsContainer_tags_1)
		/sizeof(asn_DEF_GeneralizedLanePositionsContainer_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_GeneralizedLanePositionsContainer_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		GeneralizedLanePositionsContainer_constraint
	},
	asn_MBR_GeneralizedLanePositions_1,
	1,	/* Single element */
	&asn_SPC_GeneralizedLanePositions_specs_1	/* Additional specs */
};
