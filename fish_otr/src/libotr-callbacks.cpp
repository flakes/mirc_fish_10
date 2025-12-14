#include "mirc-otr-internal.h"
#include "otr-engine.h"

extern "C" static OtrlPolicy ops_policy(void *opdata, ConnContext *context)
{
	return OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;
}

extern "C" static void ops_create_privkey(void *opdata, const char *accountname, const char *protocol)
{
	// key_gen_run(user_state_global, accountname);
}

extern "C" static void ops_inject_msg(void *opdata, const char *accountname, const char *protocol, const char *recipient, const char *message)
{
	Sleep(1);
	/*SERVER_REC *irssi = opdata;

	IRSSI_DEBUG("Inject msg:\n[%s]", message);
	irssi_send_message(irssi, recipient, message);*/
}

// Gone secure.
extern "C" static void ops_secure(void *opdata, ConnContext *context)
{

}

// Gone insecure.
extern "C" static void ops_insecure(void *opdata, ConnContext *context)
{

}

extern "C" static int ops_max_msg(void *opdata, ConnContext *context)
{
	return OTR_MAX_MSG_SIZE;
}

extern "C" static void ops_handle_msg_event(void *opdata, OtrlMessageEvent msg_event, ConnContext *context, const char *message, gcry_error_t err)
{
}

// A context changed.
extern "C" static void ops_up_ctx_list(void *opdata)
{
	// otr_status_change(opdata, NULL, OTR_STATUS_CTX_UPDATE);
}

extern "C" static void ops_write_fingerprints(void *data)
{
	// key_write_fingerprints(user_state_global);
}

extern "C" static int ops_is_logged_in(void *opdata, const char *accountname, const char *protocol, const char *recipient)
{
	/*int ret;
	SERVER_REC *irssi = opdata;

	if (irssi) 
		ret = 1;
	}
	else {
		ret = 0;
	}

	IRSSI_DEBUG("User %s %s logged in", accountname,
		(ret == 0) ? "not" : "");

	return ret;*/
	return 0;
}

extern "C" static void ops_create_instag(void *opdata, const char *accountname, const char *protocol)
{
	/*otrl_instag_generate(user_state_global->otr_state, "/dev/null",
		accountname, protocol);
	key_write_instags(user_state_global);*/
}

extern "C" static void ops_smp_event(void *opdata, OtrlSMPEvent smp_event, ConnContext *context, unsigned short progress_percent, char *question)
{
}

extern "C" static void ops_timer_control(void *opdata, unsigned int interval)
{
}

extern "C" static const char *ops_otr_error_message(void *opdata, ConnContext *context, OtrlErrorCode code)
{
	char *msg = NULL;

	switch (code) {
	case OTRL_ERRCODE_NONE:
		break;
	case OTRL_ERRCODE_ENCRYPTION_ERROR:
		msg = _strdup("Error occurred encrypting message.");
		break;
	case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
		if (context) {
			msg = _strdup("You sent encrypted data which was unexpected");
		}
		break;
	case OTRL_ERRCODE_MSG_UNREADABLE:
		msg = _strdup("You transmitted an unreadable encrypted message");
		break;
	case OTRL_ERRCODE_MSG_MALFORMED:
		msg = _strdup("You transmitted a malformed data message.");
		break;
	}

	return msg;
}

extern "C" static void ops_otr_error_message_free(void *opdata, const char *err_msg)
{
	if (err_msg)
		free(const_cast<char*>(err_msg));
}

OtrlMessageAppOps COTREngine::ms_opsCallbacks = {
	ops_policy,
	ops_create_privkey,
	ops_is_logged_in,
	ops_inject_msg,
	ops_up_ctx_list,
	NULL, /* new_fingerprint */
	ops_write_fingerprints,
	ops_secure,
	ops_insecure,
	NULL, /* still_secure */
	ops_max_msg,
	NULL, /* account_name */
	NULL, /* account_name_free */
	NULL, /* received_symkey */
	ops_otr_error_message,
	ops_otr_error_message_free,
	NULL, /* resent_msg_prefix */
	NULL, /* resent_msg_prefix_free */
	ops_smp_event,
	ops_handle_msg_event,
	ops_create_instag,
	NULL, /* convert_msg */
	NULL, /* convert_free */
	ops_timer_control,
};
