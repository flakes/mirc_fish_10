#include "fish-internal.h"
#include <openssl/blowfish.h>

/* uses code from DIRTIRC (GPLv2) */


union bf_data {
	struct {
		unsigned long left;
		unsigned long right;
	} lr;
	BF_LONG bf_long;
};

static const std::string fish_base64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


static void remove_bad_chars(std::string &str)
{
	std::string::size_type i;
	while (i = str.find('\x00', 0), i != std::string::npos) str.erase(i, 1);
	while (i = str.find_first_of("\x0d\x0a"), i != std::string::npos) str.erase(i, 1);
}


void blowfish_encrypt(const std::string& ain, std::string &out, const std::string &key)
{
	std::string in(ain);
	int datalen = in.size();
	if (datalen % 8 != 0) {
		datalen += 8 - (datalen % 8);
		in.resize(datalen, 0);
	}
	out.clear();
	BF_KEY bf_key;
	BF_set_key(&bf_key, key.size(), (unsigned char*)key.data());
	bf_data data;
	unsigned long i, part;
	unsigned char *s = (unsigned char*)in.data();
	for (i = 0; i < in.size(); i += 8) {
		data.lr.left = *s++ << 24;
		data.lr.left += *s++ << 16;
		data.lr.left += *s++ << 8;
		data.lr.left += *s++;
		data.lr.right = *s++ << 24;
		data.lr.right += *s++ << 16;
		data.lr.right += *s++ << 8;
		data.lr.right += *s++;
		BF_encrypt(&data.bf_long, &bf_key);
		for (part = 0; part < 6; part++) {
			out += fish_base64[data.lr.right & 0x3f];
			data.lr.right = data.lr.right >> 6;
		}
		for (part = 0; part < 6; part++) {
			out += fish_base64[data.lr.left & 0x3f];
			data.lr.left = data.lr.left >> 6;
		}
	}
}


int blowfish_decrypt(const std::string& ain, std::string &out, const std::string &key)
{
	std::string in(ain);
	bool has_cut = false;
	if (in.size() < 12) return -1;
	int cut_off = in.size() % 12;
	if (cut_off > 0) {
		has_cut = true;
		in.erase(in.size() - cut_off, cut_off);
	}
	if (in.find_first_not_of(fish_base64, 0) != std::string::npos) return -1;
	out.clear();
	BF_KEY bf_key;
	BF_set_key(&bf_key, key.size(), (unsigned char*)key.data());
	bf_data data;
	unsigned long val, i, part;
	char *s = (char*)in.data();
	for (i = 0; i < in.size(); i += 12) {
		data.lr.left = 0;
		data.lr.right = 0;
		for (part = 0; part < 6; part++) {
			if ((val = fish_base64.find(*s++)) == std::string::npos) return -1;
			data.lr.right |= val << part * 6;
		}
		for (part = 0; part < 6; part++) {
			if ((val = fish_base64.find(*s++)) == std::string::npos) return -1;
			data.lr.left |= val << part * 6;
		}
		BF_decrypt(&data.bf_long, &bf_key);
		for (part = 0; part < 4; part++) out += (data.lr.left & (0xff << ((3 - part) * 8))) >> ((3 - part) * 8);
		for (part = 0; part < 4; part++) out += (data.lr.right & (0xff << ((3 - part) * 8))) >> ((3 - part) * 8);
	}
	remove_bad_chars(out);
	return (has_cut ? 1 : 0);
}

