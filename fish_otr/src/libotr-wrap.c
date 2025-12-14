// keep this a C file to be able to use OTR + g* headers without modifications
//  (they don't have extern "C") ...

#include "libotr-wrap.h"

gcry_error_t w_otrl_init()
{
	return otrl_init(OTRL_VERSION_MAJOR, OTRL_VERSION_MINOR, OTRL_VERSION_SUB);
}

const char *w_otrl_version()
{
	return otrl_version();
}

OtrlUserState w_otrl_userstate_create()
{
	return otrl_userstate_create();
}

void w_otrl_userstate_free(OtrlUserState us)
{
	otrl_userstate_free(us);
}

gcry_error_t w_otrl_privkey_generate_FILEp(OtrlUserState us, FILE *privf, const char *accountname)
{
	return otrl_privkey_generate_FILEp(us, privf, accountname, OTR_PROTOCOL_ID);
}

gcry_error_t w_otrl_privkey_read_FILEp(OtrlUserState us, FILE *privf)
{
	return otrl_privkey_read_FILEp(us, privf);
}

gcry_error_t w_otrl_privkey_read_fingerprints_FILEp(OtrlUserState us, FILE *storef, f_add_appdata add_app_data, void *data)
{
	return otrl_privkey_read_fingerprints_FILEp(us, storef, add_app_data, data);
}

gcry_error_t w_otrl_instag_read_FILEp(OtrlUserState us, FILE *instf)
{
	return otrl_instag_read_FILEp(us, instf);
}

gcry_error_t w_otrl_message_sending(OtrlUserState us, const OtrlMessageAppOps *ops, void *opdata, const char *accountname,
	const char *recipient, otrl_instag_t instag, const char *original_msg, OtrlTLV *tlvs, char **messagep, OtrlFragmentPolicy fragPolicy,
	ConnContext **contextp, f_add_appdata add_appdata, void *data)
{
	return otrl_message_sending(us, ops, opdata, accountname, OTR_PROTOCOL_ID, recipient, instag, original_msg, tlvs, messagep, fragPolicy, contextp, add_appdata, data);
}
