#include "fish-internal.h"
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/sha.h>


static void DH1080_Base64_Encode(std::string& a_string)
{
	std::string l_b64 = Base64_Encode(a_string);

	if(l_b64.find('=') == std::string::npos)
	{
		a_string = l_b64 + 'A';
	}
	else
	{
		// remove equal signs:
		a_string.clear(); a_string.reserve(l_b64.size());
		for(std::string::size_type p = 0; p < l_b64.size(); p++)
			if(l_b64[p] != '=') a_string += l_b64[p];
	}
}


static void DH1080_Base64_Decode(std::string& a_string)
{
	if(a_string.size() % 4 == 1 && a_string[a_string.size() - 1] == 'A')
	{
		a_string.erase(a_string.size() - 1, 1);
	}

	while(a_string.size() % 4)
	{
		a_string += '=';
	}

	a_string = Base64_Decode(a_string);
}


static std::string DH1080_SHA256(const char* a_data, size_t a_len)
{
	char l_shaBuf[SHA256_DIGEST_LENGTH];
	SHA256_CTX l_ctx;

	SHA256_Init(&l_ctx);
	SHA256_Update(&l_ctx, a_data, a_len);
	SHA256_Final((unsigned char*)&l_shaBuf, &l_ctx);

	std::string l_result((char*)&l_shaBuf, SHA256_DIGEST_LENGTH);
	DH1080_Base64_Encode(l_result);

	return l_result;
}


#define DH1080_PRIME "++ECLiPSE+is+proud+to+present+latest+FiSH+release+featuring+even+more+security+for+you+++shouts+go+out+to+TMG+for+helping+to+generate+this+cool+sophie+germain+prime+number++++/C32L"


static std::string DhKeyToStr(DH* a_dh, bool a_privKey)
{
	std::string l_result;

	if(a_dh && a_dh->g && a_dh->p)
	{
		int l_bufSize = DH_size(a_dh);
		char *l_key = new char[l_bufSize];

		if(l_bufSize && l_key)
		{
			if(BN_bn2bin((a_privKey ? a_dh->priv_key : a_dh->pub_key), (unsigned char*)l_key))
			{
				l_result.append(l_key, l_bufSize);
				DH1080_Base64_Encode(l_result);
			}
		}

		delete[] l_key;
	}

	return l_result;
}


static bool _DH1080_Init(DH** a_dh)
{
	DH *l_dh = *a_dh = DH_new();

	if(l_dh)
	{
		l_dh->g = BN_new();
		l_dh->p = BN_new();

		if(l_dh->g && l_dh->p)
		{
			BN_dec2bn(&l_dh->g, "2");

			std::string l_primeStr = DH1080_PRIME;
			DH1080_Base64_Decode(l_primeStr);
			
			if(!l_primeStr.empty() && BN_bin2bn((unsigned char*)l_primeStr.data(), l_primeStr.size(), l_dh->p))
			{
				return true;
			}
		}

		DH_free(l_dh);
	}

	return false;
}


bool DH1080_Generate(std::string& ar_priv, std::string& ar_pub)
{
	DH* l_dh;

	if(_DH1080_Init(&l_dh))
	{
		int l_check;

		if(DH_check(l_dh, &l_check) == 1 && l_check == 0)
		{
			if(DH_generate_key(l_dh) == 1)
			{
				// private and public keys have been generated!

				ar_priv = DhKeyToStr(l_dh, true);
				ar_pub = DhKeyToStr(l_dh, false);

				DH_free(l_dh);

				return true;
			}
		}

		DH_free(l_dh);
	}

	return false;
}


std::string DH1080_Compute(const std::string& a_priv, const std::string& a_pub)
{
	std::string l_result;
	DH* l_dh;

	if(_DH1080_Init(&l_dh))
	{
		l_dh->priv_key = BN_new();

		std::string l_priv(a_priv);
		DH1080_Base64_Decode(l_priv);

		if(l_dh->priv_key && l_priv.size() == 135 &&
			BN_bin2bn((unsigned char*)l_priv.data(), l_priv.size(), l_dh->priv_key))
		{
			BIGNUM* l_remotePubKey = BN_new();

			std::string l_pub(a_pub);
			DH1080_Base64_Decode(l_pub);

			if(l_remotePubKey && l_pub.size() == 135 &&
				BN_bin2bn((unsigned char*)l_pub.data(), l_pub.size(), l_remotePubKey))
			{
				int l_bufSize = DH_size(l_dh);
				char *l_key = new char[l_bufSize];

				if(l_bufSize && l_key)
				{
					int l_keySize = DH_compute_key((unsigned char*)l_key, l_remotePubKey, l_dh);

					if(l_keySize == l_bufSize)
					{
						l_result = DH1080_SHA256(l_key, l_keySize);
					}
				}

				delete[] l_key;
			}

			if(l_remotePubKey) BN_free(l_remotePubKey);
		}

		DH_free(l_dh);
	}

	return l_result;
}

