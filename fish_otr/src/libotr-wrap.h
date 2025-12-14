#pragma once

#include "gcrypt.h"

//
// cannot wrap these #includes in extern "C" because they include Windows
// headers which then causes other breakage.
//
#include "proto.h"
#include "message.h"
#include "userstate.h"
#include "privkey.h"
#include "instag.h"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef void(*f_add_appdata)(void *data, ConnContext *context);

	//
	// wrapped calls into libotr:
	//

	gcry_error_t w_otrl_init();
	const char *w_otrl_version();

	OtrlUserState w_otrl_userstate_create();
	void w_otrl_userstate_free(OtrlUserState);

	gcry_error_t w_otrl_privkey_generate_FILEp(OtrlUserState, FILE *, const char *);
	gcry_error_t w_otrl_privkey_read_FILEp(OtrlUserState, FILE *);
	gcry_error_t w_otrl_privkey_read_fingerprints_FILEp(OtrlUserState, FILE *, f_add_appdata, void *);
	gcry_error_t w_otrl_instag_read_FILEp(OtrlUserState us, FILE *);

	gcry_error_t w_otrl_message_sending(OtrlUserState, const OtrlMessageAppOps *, void *, const char *,
		const char *, otrl_instag_t, const char *, OtrlTLV *, char **, OtrlFragmentPolicy, ConnContext **, f_add_appdata, void *);

#ifdef __cplusplus
}
#endif

#define OTR_PROTOCOL_ID "IRC"
#define OTR_MAX_MSG_SIZE 400
