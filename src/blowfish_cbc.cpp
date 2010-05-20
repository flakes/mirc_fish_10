#include "fish-internal.h"
#include <openssl/evp.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>

/*
Mircryption compatible Blowfish routines using OpenSSL.
*/


static bool s_PrngSeeded = false;


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
	EVP_CIPHER_CTX l_ctx;
	const unsigned char iv[8] = {0};
	/* for some f*cked up reason, Mircryption's CBC blowfish does not use an
		explicit IV, but prepends 8 bytes of random data to the actual string
		instead, so we have to do this too... */
	int l_keyLen = (a_key.size() <= 56 ? (int)a_key.size() : 56);

	// init struct for encryption:
	EVP_CIPHER_CTX_init(&l_ctx);
	EVP_CipherInit_ex(&l_ctx, EVP_bf_cbc(), NULL, NULL, NULL, 1);

	// set options:
	EVP_CIPHER_CTX_set_key_length(&l_ctx, l_keyLen);
	EVP_CIPHER_CTX_set_padding(&l_ctx, 0); // disable auto padding. Required for Mircryption compatibility.

	// actually initialize session context:
	EVP_CipherInit_ex(&l_ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(a_key.c_str()), iv, 1);

	// prepare buffers:
	size_t l_inBufSize = a_in.size();
	if (l_inBufSize % 8 != 0) {
		l_inBufSize += 8 - (l_inBufSize % 8);
	}
	l_inBufSize += 8; // for the IV data

	char *l_bufIn = new char[l_inBufSize];
	memset(l_bufIn, 0, l_inBufSize); // important for padding
	
	ar_out.clear();

	// generate IV:
	if(!s_PrngSeeded)
	{
		s_PrngSeeded = true;
		RAND_screen();
	}
	unsigned char l_realIv[8];
	if(!RAND_bytes(l_realIv, 8))
	{
		// fallback:
		RAND_pseudo_bytes(l_realIv, 8);
	}
	// ok we have an IV.
	memcpy(l_bufIn, l_realIv, 8);
	memcpy(l_bufIn + 8, a_in.c_str(), a_in.size());

	// encrypt data:
	_blowfish_cipher_walk(&l_ctx, l_bufIn, l_inBufSize, ar_out);

	delete[] l_bufIn;
	EVP_CIPHER_CTX_cleanup(&l_ctx);

	// do base64 for easier handling outside this function:
	ar_out = Base64_Encode(ar_out);
}


int blowfish_decrypt_cbc(const std::string& a_in, std::string &ar_out, const std::string &a_key)
{
	EVP_CIPHER_CTX l_ctx;
	const unsigned char iv[8] = {0};
	int l_keyLen = (a_key.size() <= 56 ? (int)a_key.size() : 56);

	// de-base64:
	std::string l_in = Base64_Decode(a_in);
	if(l_in.empty())
	{
		return -1;
	}
	bool l_beenCut = (l_in.size() % 8 != 0);

	if(l_beenCut)
	{
		l_in.erase(l_in.size() - (l_in.size() % 8));
	}

	// init struct for decryption:
	EVP_CIPHER_CTX_init(&l_ctx);
	EVP_CipherInit_ex(&l_ctx, EVP_bf_cbc(), NULL, NULL, NULL, 0);

	// set options:
	EVP_CIPHER_CTX_set_key_length(&l_ctx, l_keyLen);
	EVP_CIPHER_CTX_set_padding(&l_ctx, 0); // MUST be the same setting used during encryption.

	// actually initialize session context:
	EVP_CipherInit_ex(&l_ctx, NULL, NULL, reinterpret_cast<const unsigned char*>(a_key.c_str()), iv, 0);

	// decrypt...
	bool l_success = _blowfish_cipher_walk(&l_ctx, l_in.c_str(), l_in.size(), ar_out);

	EVP_CIPHER_CTX_cleanup(&l_ctx);

	// used to do if(l_success) here, but even if the decryption was not successful, there
	// might be *some* data in the out buffer, so we should always do this:
	ar_out.erase(0, 8); // remove IV data
	remove_bad_chars(ar_out);

	return (l_success ? (l_beenCut ? 1 : 0) : -1);
}
