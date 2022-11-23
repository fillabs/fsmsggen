/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_AdverseWeatherCondition_PrecipitationSubCauseCode_H_
#define	_AdverseWeatherCondition_PrecipitationSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AdverseWeatherCondition_PrecipitationSubCauseCode {
	AdverseWeatherCondition_PrecipitationSubCauseCode_unavailable	= 0,
	AdverseWeatherCondition_PrecipitationSubCauseCode_heavyRain	= 1,
	AdverseWeatherCondition_PrecipitationSubCauseCode_heavySnowfall	= 2,
	AdverseWeatherCondition_PrecipitationSubCauseCode_softHail	= 3
} e_AdverseWeatherCondition_PrecipitationSubCauseCode;

/* AdverseWeatherCondition-PrecipitationSubCauseCode */
typedef long	 AdverseWeatherCondition_PrecipitationSubCauseCode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AdverseWeatherCondition_PrecipitationSubCauseCode;
asn_struct_free_f AdverseWeatherCondition_PrecipitationSubCauseCode_free;
asn_struct_print_f AdverseWeatherCondition_PrecipitationSubCauseCode_print;
asn_constr_check_f AdverseWeatherCondition_PrecipitationSubCauseCode_constraint;
ber_type_decoder_f AdverseWeatherCondition_PrecipitationSubCauseCode_decode_ber;
der_type_encoder_f AdverseWeatherCondition_PrecipitationSubCauseCode_encode_der;
per_type_decoder_f AdverseWeatherCondition_PrecipitationSubCauseCode_decode_uper;
per_type_encoder_f AdverseWeatherCondition_PrecipitationSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AdverseWeatherCondition_PrecipitationSubCauseCode_H_ */
#include <asn_internal.h>
