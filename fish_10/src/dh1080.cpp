#include "fish-internal.h"
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <mutex>


static void DH1080_Base64_Encode(std::string& a_string)
{
	std::string l_b64 = Base64_Encode(a_string);

	if (l_b64.find('=') == std::string::npos)
	{
		a_string = l_b64 + 'A';
	}
	else
	{
		// remove equal signs:
		a_string.clear(); a_string.reserve(l_b64.size());
		for (std::string::size_type p = 0; p < l_b64.size(); p++)
			if (l_b64[p] != '=') a_string += l_b64[p];
	}
}


static void DH1080_Base64_Decode(std::string& a_string)
{
	if (a_string.size() % 4 == 1 && a_string[a_string.size() - 1] == 'A')
	{
		a_string.erase(a_string.size() - 1, 1);
	}

	while (a_string.size() % 4)
	{
		a_string += '=';
	}

	a_string = Base64_Decode(a_string);
}


static std::string DH1080_SHA256(const char* a_data, size_t a_len)
{
	char l_shaBuf[EVP_MAX_MD_SIZE] = { 0 };
	size_t l_digestLength = 0;

	if (EVP_Q_digest(nullptr, "SHA256", nullptr, a_data, a_len, reinterpret_cast<unsigned char*>(l_shaBuf), &l_digestLength))
	{
		std::string l_result(l_shaBuf, l_digestLength);

		DH1080_Base64_Encode(l_result);

		return l_result;
	}

	return {};
}


#define DH1080_PRIME "++ECLiPSE+is+proud+to+present+latest+FiSH+release+featuring+even+more+security+for+you+++shouts+go+out+to+TMG+for+helping+to+generate+this+cool+sophie+germain+prime+number++++/C32L"
static std::mutex g_dhInitCheckMutex;
static bool g_dhInitChecked = false;

static std::string DhKeyToStr(DH* a_dh, bool a_privKey)
{
	std::string l_result;

	if (a_dh && DH_size(a_dh) < 10240)
	{
		const size_t l_bufSize = DH_size(a_dh);
		std::vector<char> l_keyBuf;
		l_keyBuf.resize(l_bufSize, 0);

		const BIGNUM* key = (a_privKey ? DH_get0_priv_key(a_dh) : DH_get0_pub_key(a_dh));

		if (key && BN_bn2binpad(key, (unsigned char*)l_keyBuf.data(), l_bufSize))
		{
			l_result.append(l_keyBuf.data(), l_bufSize);
			DH1080_Base64_Encode(l_result);
		}
	}

	return l_result;
}


static bool _dh_init_check(DH* a_dh)
{
	std::lock_guard<std::mutex> l_initLock(g_dhInitCheckMutex);

	if (!g_dhInitChecked)
	{
		int l_check;

		if (DH_check(a_dh, &l_check) == 1 && l_check == 0)
		{
			g_dhInitChecked = true;
		}
	}

	return g_dhInitChecked;
}


static bool _DH1080_Init(DH** a_dh)
{
	DH* l_dh = DH_new();

	if (l_dh)
	{
		BIGNUM* g = BN_new();
		BIGNUM* p = BN_new();

		if (g && p)
		{
			BN_dec2bn(&g, "00002"); // 0-padded for hex-editing alternate g generator

			std::string l_primeStr = DH1080_PRIME;
			DH1080_Base64_Decode(l_primeStr);

			if (!l_primeStr.empty() && BN_bin2bn((unsigned char*)l_primeStr.data(), l_primeStr.size(), p))
			{
				DH_set0_pqg(l_dh, p, nullptr, g);

				if (_dh_init_check(l_dh))
				{
					*a_dh = l_dh;

					return true;
				}
			}
		}

		DH_free(l_dh);
	}

	return false;
}


bool DH1080_Generate(std::string& ar_priv, std::string& ar_pub)
{
	DH* l_dh;

	if (_DH1080_Init(&l_dh))
	{
		if (DH_generate_key(l_dh) == 1)
		{
			// private and public keys have been generated!

			ar_priv = DhKeyToStr(l_dh, true);
			ar_pub = DhKeyToStr(l_dh, false);

			DH_free(l_dh);

			return true;
		}

		DH_free(l_dh);
	}

	return false;
}


std::string DH1080_Compute(const std::string& a_priv, const std::string& a_pub)
{
	std::string l_result;
	DH* l_dh;

	if (_DH1080_Init(&l_dh))
	{
		BIGNUM* priv_key = BN_new();

		std::string l_priv(a_priv);
		DH1080_Base64_Decode(l_priv);

		if (priv_key && l_priv.size() == 135 &&
			BN_bin2bn((unsigned char*)l_priv.data(), l_priv.size(), priv_key))
		{
			DH_set0_key(l_dh, nullptr, priv_key);

			BIGNUM* l_remotePubKey = BN_new();

			std::string l_pub(a_pub);
			DH1080_Base64_Decode(l_pub);

			if (l_remotePubKey && l_pub.size() == 135 &&
				BN_bin2bn((unsigned char*)l_pub.data(), l_pub.size(), l_remotePubKey))
			{
				std::vector<char> l_keyBuf;
				l_keyBuf.resize(DH_size(l_dh), 0);

				const int l_keySize = DH_compute_key(reinterpret_cast<unsigned char*>(l_keyBuf.data()), l_remotePubKey, l_dh);

				if (l_keySize > 0)
				{
					if (l_keySize < DH_size(l_dh))
					{
						std::vector<char> l_paddedBuf;
						l_paddedBuf.resize(DH_size(l_dh), 0);

						memcpy_s(l_paddedBuf.data() + l_paddedBuf.size() - l_keySize, l_paddedBuf.size(), l_keyBuf.data(), l_keySize);

						l_result = DH1080_SHA256(l_paddedBuf.data(), l_paddedBuf.size());
					}
					else
					{
						l_result = DH1080_SHA256(l_keyBuf.data(), l_keyBuf.size());
					}
				}
			}

			if (l_remotePubKey) BN_free(l_remotePubKey);
		}

		DH_free(l_dh);
	}

	return l_result;
}

