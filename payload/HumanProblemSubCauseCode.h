/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_HumanProblemSubCauseCode_H_
#define	_HumanProblemSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HumanProblemSubCauseCode {
	HumanProblemSubCauseCode_unavailable	= 0,
	HumanProblemSubCauseCode_glycemiaProblem	= 1,
	HumanProblemSubCauseCode_heartProblem	= 2
} e_HumanProblemSubCauseCode;

/* HumanProblemSubCauseCode */
typedef long	 HumanProblemSubCauseCode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HumanProblemSubCauseCode;
asn_struct_free_f HumanProblemSubCauseCode_free;
asn_struct_print_f HumanProblemSubCauseCode_print;
asn_constr_check_f HumanProblemSubCauseCode_constraint;
ber_type_decoder_f HumanProblemSubCauseCode_decode_ber;
der_type_encoder_f HumanProblemSubCauseCode_encode_der;
jer_type_encoder_f HumanProblemSubCauseCode_encode_jer;
per_type_decoder_f HumanProblemSubCauseCode_decode_uper;
per_type_encoder_f HumanProblemSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _HumanProblemSubCauseCode_H_ */
#include <asn_internal.h>
