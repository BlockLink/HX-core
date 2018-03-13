/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: main.cpp
* Date: 2018-01-11
*/

#include <graphene/crosschain_privatekey_management/private_key.hpp>
#include <graphene/crosschain_privatekey_management/database_privatekey.hpp>
#include "fc/crypto/base58.hpp"
#include <bitcoin/bitcoin.hpp>

#include <string> 
#include <vector> 
#include <iostream> 



// 
// std::string key_to_compressed_wif(const fc::sha256& secret)
// {
//     //one byte for prefix, one byte for compressed sentinel
// 	const size_t size_of_data_to_hash = sizeof(secret) + 2;	
// 	const size_t size_of_hash_bytes = 4;
// 	char data[size_of_data_to_hash  + size_of_hash_bytes];
// 	data[0] = (char)0x80;
// 	memcpy(&data[1], (char*)&secret, sizeof(secret));
// 	data[size_of_data_to_hash - 1] = (char)0x01;
// 	fc::sha256 digest = fc::sha256::hash(data, size_of_data_to_hash);
// 	digest = fc::sha256::hash(digest);
// 	memcpy(data + size_of_data_to_hash, (char*)&digest, size_of_hash_bytes);
// 	return fc::to_base58(data, sizeof(data));
// }
// std::string key_to_compressed_wif(const fc::ecc::private_key& key)
// {
// 	return key_to_compressed_wif(key.get_secret());
// }


int main(int argc, char** argv)
{
	using namespace graphene::privatekey_management;
	
// 	// test private key generation
// 	btc_privatekey btc_priv;
// 	auto btc_wif_key = btc_priv.get_wif_key();
// 	printf("btc wif key: %s\n", btc_wif_key.c_str());
// 	auto btc_addr = btc_priv.get_address();
// 	printf("btc address: %s\n", btc_addr.c_str());
// 
// 	auto import_btc_priv_key = btc_priv.import_private_key(btc_wif_key);
// 	btc_privatekey import_btc_priv(*import_btc_priv_key);
// 	btc_wif_key = import_btc_priv.get_wif_key();
// 	printf("imported btc wif key: %s\n", btc_wif_key.c_str());
// 
// 
// 	ltc_privatekey ltc_priv;
// 	auto ltc_wif_key = ltc_priv.get_wif_key();
// 	printf("ltc wif key: %s\n", ltc_wif_key.c_str());
// 	auto ltc_addr = ltc_priv.get_address();
// 	printf("ltc address: %s\n", ltc_addr.c_str());
// 	auto import_ltc_priv_key = ltc_priv.import_private_key(ltc_wif_key);
// 	ltc_privatekey import_ltc_priv(*import_ltc_priv_key);
// 	ltc_wif_key = import_ltc_priv.get_wif_key();
// 	printf("imported ltc wif key: %s\n", ltc_wif_key.c_str());



// 	database_privatekey db_priv;
// 	db_priv.open("C:\\Users\\wensw\\Desktop\\blocklink\\data_dir");
// 	std::string password = "123456";
// 	auto checksum = fc::sha512::hash(password.c_str(), password.size());
// 

// 	for (auto i = 0; i < 10; i++)
// 	{
// 		printf("current index: %d\n", i + 1);
// 
// 		btc_privatekey btc_priv;
// 		auto btc_wif_key = btc_priv.get_wif_key(btc_priv.get_private_key());
// 		printf("btc wif key: %s\n", btc_wif_key.c_str());
// 		auto btc_addr = btc_priv.get_address(btc_priv.get_private_key());
// 		printf("btc address: %s\n", btc_addr.c_str());
// 		auto import_btc_priv_key = btc_priv.import_private_key(btc_wif_key);
// 		btc_wif_key = btc_priv.get_wif_key(*import_btc_priv_key);
// 		printf("imported btc wif key: %s\n", btc_wif_key.c_str());
// 
// 
// 
// 		crosschain_privatekey_data data;
// 		data.id = i+1;
// 		data.addr = btc_priv.get_address(btc_priv.get_private_key());
// 		data.wif_key = btc_priv.get_wif_key(btc_priv.get_private_key());
// 
// 	
// 
// 		db_priv.store(data, checksum);
// 	}	
// 
// 	printf("\n");
// 	auto result = db_priv.fetch_by_id(3, checksum);
// 	printf("%s\n", result->wif_key.c_str());
// 
// 	auto max_id = db_priv.fetch_current_max_id();
// 	printf("%d\n", max_id);


	btc_privatekey priv;
	printf("wif key is %s\n", priv.get_wif_key().c_str());
	printf("address is %s\n", priv.get_address().c_str());

	std::string script = "dup hash160 [b5843e180a4360bdbf4bcd9cdd37c311bb9fcb64] equalverify checksig";
	std::string raw_trx = "02000000019463a8d3eb08b33ea75526510a2f88b63deb599021c92f1d5f78dce888262ab10000000000ffffffff01605af405000000001976a914f04d7bc2c9c2ce2ccefd9ebcd24c60a73caa1df588ac00000000";
	auto result = priv.sign_trx(script, raw_trx);
	printf("result is %s", result.c_str());

	std::string msg = "Who is John Galt?";
	result = priv.sign_message(msg);
	printf("result is %s", result.c_str());


	
// 
// 	btc_privatekey priv;
// 	std::string wif = priv.get_wif_key();
// 	printf("the wif is %s\n", wif.c_str());
// 
// 	libbitcoin::wallet::ec_private libbitcoin_priv(wif);
// 	libbitcoin::ec_secret secret = libbitcoin_priv.secret();
// 
// 	std::string hex_string = "394fcb53c3897424646f31361eedb6b0c159cbe2e72415b61a0cc776d8abf446";
// 	libbitcoin::data_chunk  data;
// 	libbitcoin::decode_base16(data, hex_string);
// 	printf("the size is %d\n", data.size());
// 	libbitcoin::hash_digest  hash;
// 	std::copy(data.begin(), data.end(), hash.begin());
// 
// 	libbitcoin::ec_signature  result;
// 
// 	libbitcoin::sign(result, secret, hash);
// 	printf("the result is %s\n", libbitcoin::encode_base16(result).c_str());
// 
// 	libbitcoin::der_signature out;
// 	printf("the result is %s\n", libbitcoin::encode_base16(out).c_str());


	getchar();
	return 0;
}



