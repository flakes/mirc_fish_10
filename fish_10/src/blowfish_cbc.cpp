#include "fish-internal.h"
#include <openssl/evp.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <mutex>

/*
Mircryption compatible Blowfish routines using OpenSSL.
*/

static EVP_CIPHER* GetBlowfishCbcCipher()
{
	static std::mutex s_initLock;
	static EVP_CIPHER* s_cbc = nullptr;

	std::lock_guard<std::mutex> lock(s_initLock);

	if (s_cbc == nullptr)
	{
		s_cbc = EVP_CIPHER_fetch(nullptr, "BF-CBC", "provider=legacy");
	}

	return s_cbc;
}


// buffer loop for both en- and decryption.
static bool _blowfish_cipher_walk(EVP_CIPHER_CTX *a_ctx, const char* a_bufIn, size_t a_inSize, std::string &ar_out)
{
	size_t l_bytesLeft = a_inSize;
	const char *l_bufPtr = a_bufIn;
	unsigned char l_tmpBuf[256];
	int l_outLen;

	while(l_bytesLeft > 0)
	{
		size_t l_inSize = (l_bytesLeft > 256 ? 256 : l_bytesLeft);

		if(!EVP_CipherUpdate(a_ctx, l_tmpBuf, &l_outLen, reinterpret_cast<const unsigned char*>(l_bufPtr), l_inSize))
		{
			// ZOMG! Error!
			return false;
		}

		ar_out.append(reinterpret_cast<char*>(l_tmpBuf), l_outLen);
		l_bytesLeft -= l_inSize;
		l_bufPtr += l_inSize;
	}

	bool l_success = (EVP_CipherFinal_ex(a_ctx, l_tmpBuf, &l_outLen) != 0);

	if(l_success)
	{
		ar_out.append(reinterpret_cast<char*>(l_tmpBuf), l_outLen);
	}

	return l_success;
}


void blowfish_encrypt_cbc(const std::string& a_in, std::string &ar_out, const std::string &a_key)
{
	const unsigned char iv[8] = {0};
	/* for some f*cked up reason, Mircryption's CBC blowfish does not use an
		explicit IV, but prepends 8 bytes of random data to the actual string
		instead, so we have to do this too... */
	const int l_keyLen = (a_key.size() <= 56 ? (int)a_key.size() : 56);

	// init struct for encryption:
	EVP_CIPHER_CTX* l_ctx = EVP_CIPHER_CTX_new();

	if (!EVP_CipherInit_ex2(l_ctx, GetBlowfishCbcCipher(), nullptr, nullptr,1, nullptr)) {
#ifdef _DEBUG
		::OutputDebugStringA(ERR_error_string(ERR_get_error(), nullptr));
#endif

		EVP_CIPHER_CTX_free(l_ctx);

		return;
	}

	// set options:
	EVP_CIPHER_CTX_set_key_length(l_ctx, l_keyLen);
	EVP_CIPHER_CTX_set_padding(l_ctx, 0); // disable auto padding. Required for Mircryption compatibility.

	// actually initialize session context:
	if (!EVP_CipherInit_ex2(l_ctx, nullptr, reinterpret_cast<const unsigned char*>(a_key.c_str()), iv, 1, nullptr)) {
#ifdef _DEBUG
		::OutputDebugStringA(ERR_error_string(ERR_get_error(), nullptr));
#endif

		EVP_CIPHER_CTX_free(l_ctx);

		return;
	}

	// prepare buffers:
	size_t l_inBufSize = a_in.size();
	if (l_inBufSize % 8 != 0) {
		l_inBufSize += 8 - (l_inBufSize % 8);
	}
	l_inBufSize += 8; // for the IV data

	std::vector<char> l_bufIn;
	l_bufIn.resize(l_inBufSize, 0);

	ar_out.clear();

	if (RAND_status() == 0)
	{
		RAND_poll();
	}

	// generate IV:
	unsigned char l_realIv[8];

	if (!RAND_bytes(l_realIv, 8))
	{
		return;
	}

	// ok we have an IV.
	memcpy_s(l_bufIn.data(), l_inBufSize, l_realIv, 8);
	memcpy_s(l_bufIn.data() + 8, l_inBufSize - 8, a_in.c_str(), a_in.size());

	// encrypt data:
	_blowfish_cipher_walk(l_ctx, l_bufIn.data(), l_inBufSize, ar_out);

	EVP_CIPHER_CTX_free(l_ctx);

	// do base64 for easier handling outside this function:
	ar_out = Base64_Encode(ar_out);
}


int blowfish_decrypt_cbc(const std::string& a_in, std::string &ar_out, const std::string &a_key)
{
	const unsigned char iv[8] = {0};
	const int l_keyLen = (a_key.size() <= 56 ? (int)a_key.size() : 56);

	// de-base64:
	std::string l_in = Base64_Decode(a_in);
	if(l_in.empty())
	{
		return -1;
	}

	const bool l_beenCut = (l_in.size() % 8 != 0);

	if(l_beenCut)
	{
		l_in.erase(l_in.size() - (l_in.size() % 8));
	}

	// init struct for decryption:
	EVP_CIPHER_CTX* l_ctx = EVP_CIPHER_CTX_new();

	if (!EVP_CipherInit_ex2(l_ctx, GetBlowfishCbcCipher(), nullptr, nullptr, 0, nullptr)) {
#ifdef _DEBUG
		::OutputDebugStringA(ERR_error_string(ERR_get_error(), nullptr));
#endif

		EVP_CIPHER_CTX_free(l_ctx);

		return -1;
	}

	// set options:
	EVP_CIPHER_CTX_set_key_length(l_ctx, l_keyLen);
	EVP_CIPHER_CTX_set_padding(l_ctx, 0); // MUST be the same setting used during encryption.

	// actually initialize session context:
	if (!EVP_CipherInit_ex2(l_ctx, nullptr, reinterpret_cast<const unsigned char*>(a_key.c_str()), iv, 0, nullptr)) {
#ifdef _DEBUG
		::OutputDebugStringA(ERR_error_string(ERR_get_error(), nullptr));
#endif

		EVP_CIPHER_CTX_free(l_ctx);

		return -1;
	}

	// decrypt...
	const bool l_success = _blowfish_cipher_walk(l_ctx, l_in.c_str(), l_in.size(), ar_out);

	EVP_CIPHER_CTX_free(l_ctx);

	// used to do if(l_success) here, but even if the decryption was not successful, there
	// might be *some* data in the out buffer, so we should always do this:
	ar_out.erase(0, 8); // remove IV data
	remove_bad_chars(ar_out);

	return (l_success ? (l_beenCut ? 1 : 0) : -1);
}
