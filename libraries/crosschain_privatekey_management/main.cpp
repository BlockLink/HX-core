﻿/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: main.cpp
* Date: 2018-01-11
*/

#include <graphene/crosschain_privatekey_management/private_key.hpp>
#include <graphene/crosschain_privatekey_management/database_privatekey.hpp>
#include <graphene/crosschain_privatekey_management/util.hpp>
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
	
	// test private key generation
    //btc
// 	btc_privatekey btc_priv;
// 	auto btc_wif_key = btc_priv.get_wif_key();
// 	printf("btc wif key: %s\n", btc_wif_key.c_str());
// 	auto btc_addr = btc_priv.get_address();
// 	printf("btc address: %s\n", btc_addr.c_str());
// 
//     auto btc_pub_key = btc_priv.get_public_key();
//     printf("btc public key: %s\n", btc_pub_key.c_str());
//     auto btc_addr_by_pubkey = get_address_by_pubkey(btc_pub_key, btc_priv.get_pubkey_prefix());
//     printf("btc address by public key: %s\n", btc_addr_by_pubkey.c_str());
// 
// 
// 	auto import_btc_priv_key = btc_priv.import_private_key(btc_wif_key);
// 	btc_privatekey import_btc_priv(*import_btc_priv_key);
// 	btc_wif_key = import_btc_priv.get_wif_key();
// 	printf("imported btc wif key: %s\n", btc_wif_key.c_str());
// 
// 
//     //ltc
// 	ltc_privatekey ltc_priv;
// 	auto ltc_wif_key = ltc_priv.get_wif_key();
// 	printf("ltc wif key: %s\n", ltc_wif_key.c_str());
// 	auto ltc_addr = ltc_priv.get_address();
// 	printf("ltc address: %s\n", ltc_addr.c_str());
// 
//     auto ltc_pub_key = ltc_priv.get_public_key();
//     printf("ltc public key: %s\n", ltc_pub_key.c_str());
//     auto ltc_addr_by_pubkey = get_address_by_pubkey(ltc_pub_key, ltc_priv.get_pubkey_prefix());
//     printf("btc address by public key: %s\n", ltc_addr_by_pubkey.c_str());
// 
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


// 	btc_privatekey priv;
// 	printf("wif key is %s\n", priv.get_wif_key().c_str());
// 	printf("address is %s\n", priv.get_address().c_str());
// 
// 	std::string script = "dup hash160 [b5843e180a4360bdbf4bcd9cdd37c311bb9fcb64] equalverify checksig";
// 	std::string raw_trx = "02000000019463a8d3eb08b33ea75526510a2f88b63deb599021c92f1d5f78dce888262ab10000000000ffffffff01605af405000000001976a914f04d7bc2c9c2ce2ccefd9ebcd24c60a73caa1df588ac00000000";
// 	auto result = priv.sign_trx(script, raw_trx);
// 	printf("result is %s\n", result.c_str());
// 
// 	std::string msg = "Who is John Galt?";
// 	result = priv.sign_message(msg);
// 	printf("result is %s\n", result.c_str());


	
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


//     std::vector <std::string>  my_privs;
//     my_privs.push_back("L2TtkoupXw4cYZebqUmSAEvnEh5K7pMAWEY9Tqih2CNdE7QcqR48");
//     my_privs.push_back("KyJYWeAxYoxU5wCaGQKjqi73sK1QQBDsnvyGJB5LJP1XKahVj8mr");
//     my_privs.push_back("KzzC6XzCEM6YZfYUJCJ51gvxNuxAbXaKktqXPgsMPbstm56QrwNZ");
//     my_privs.push_back("KwKKwdfnsZMxSn65EPio2Ei8uK2cdvKyAsB5Pv82gnYe6XZHAcMc");
//     my_privs.push_back("L2r9e1omHc8ivDwS1X3qo8aYrvd1kLWNMkN8Rj4XgHSVDAC1iMrc");
// 
// 
//     std::string redeemscript = "5 [03045651fb6f856ce1b27fb173e44d8bd30842d4459fa586353a69cb276384e052] [03caf30dcebba7c04e973b4afa394f0199e4c5a387faa5cec31b06dffe6592bd2e] [03b5b29f6bba2c73fe7a3a0a2fa0f1aab23c5cf827686d605e9ab15cc281ac3272] [039a935048686f7bd83d8de10ec614b1b767ce74902e25c4a67632b225c6404316] [02b7730bb1aa8289f8028fe9315c5002860bc3578c87f26abb63c9ef2ca3fcfe5f] [0262b4fc622eb191a61f209cf890799fd141d003cc6ef721c192974120d5370a4e] [02ca9c947b9a73f1819759aca131680aa0d0263c4130a2710d1a13b1d7755b9e90] 7 checkmultisig";
//     std::string raw_trx_hex = "020000000117749ee7407b9a0511b742f9510d047a5edccef7d102377e573d3757ce509c540100000000ffffffff02000e2707000000001976a91428e13ec311b8b377288d069a489a0136ef967ca788ac603572340000000017a914537b76690c6d13d89ebe5d0e029c8f1c346a9fe38700000000";
// 
//     std::vector<std::string> all_endorse;
//     for (auto wif_str : my_privs)
//     {
//         all_endorse.push_back(create_endorsement(wif_str, redeemscript, raw_trx_hex));
//     }
// 
       std::string redeemscript_hex = "552103045651fb6f856ce1b27fb173e44d8bd30842d4459fa586353a69cb276384e0522103caf30dcebba7c04e973b4afa394f0199e4c5a387faa5cec31b06dffe6592bd2e2103b5b29f6bba2c73fe7a3a0a2fa0f1aab23c5cf827686d605e9ab15cc281ac327221039a935048686f7bd83d8de10ec614b1b767ce74902e25c4a67632b225c64043162102b7730bb1aa8289f8028fe9315c5002860bc3578c87f26abb63c9ef2ca3fcfe5f210262b4fc622eb191a61f209cf890799fd141d003cc6ef721c192974120d5370a4e2102ca9c947b9a73f1819759aca131680aa0d0263c4130a2710d1a13b1d7755b9e9057ae";
//     auto result = sign_trx(all_endorse, redeemscript_hex, raw_trx_hex);

       libbitcoin::chain::script   libbitcoin_script;
//        libbitcoin_script.from_string(redeemscript);
       libbitcoin_script.from_data(libbitcoin::config::base16(redeemscript_hex), false);

       auto flags = libbitcoin::machine::rule_fork::all_rules;

       auto str = libbitcoin_script.to_string(flags);
       printf("the str is %s\n", str.c_str());
    

	getchar();
	return 0;
}



