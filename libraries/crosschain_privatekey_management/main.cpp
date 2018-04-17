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
#include "fc/crypto/base58.hpp"
#include <bitcoin/bitcoin.hpp>
#include <graphene/crosschain_privatekey_management/util.hpp>
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

namespace graphene {
	namespace privatekey_management {
		extern std::string create_endorsement_ub(const std::string& signer_wif, const std::string& redeemscript_hex, const std::string& raw_trx, int vin_index);

	}
}
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

/*
	btc_privatekey priv;

	std::string script = "OP_HASH160 97f0c041b556fbb141364790b596cd9b3b2b403b OP_EQUAL";
	std::string redeemscript = "552103045651fb6f856ce1b27fb173e44d8bd30842d4459fa586353a69cb276384e0522103caf30dcebba7c04e973b4afa394f0199e4c5a387faa5cec31b06dffe6592bd2e2103b5b29f6bba2c73fe7a3a0a2fa0f1aab23c5cf827686d605e9ab15cc281ac327221039a935048686f7bd83d8de10ec614b1b767ce74902e25c4a67632b225c64043162102b7730bb1aa8289f8028fe9315c5002860bc3578c87f26abb63c9ef2ca3fcfe5f210262b4fc622eb191a61f209cf890799fd141d003cc6ef721c192974120d5370a4e2102ca9c947b9a73f1819759aca131680aa0d0263c4130a2710d1a13b1d7755b9e9057ae";
	std::string raw_trx = "020000000117749ee7407b9a0511b742f9510d047a5edccef7d102377e573d3757ce509c540100000000ffffffff02000e2707000000001976a91428e13ec311b8b377288d069a489a0136ef967ca788ac603572340000000017a914537b76690c6d13d89ebe5d0e029c8f1c346a9fe38700000000";
	auto temp1 = graphene::privatekey_management::mutisign_trx("L2TtkoupXw4cYZebqUmSAEvnEh5K7pMAWEY9Tqih2CNdE7QcqR48",redeemscript, raw_trx);
	//std::cout << "1:" << temp1<< std::endl;
	auto temp2 = graphene::privatekey_management::mutisign_trx("KyJYWeAxYoxU5wCaGQKjqi73sK1QQBDsnvyGJB5LJP1XKahVj8mr", redeemscript, raw_trx);
	//std::cout << "2:" << temp2 << std::endl;

	if (temp1 == temp2)
	{
		std::cout << "same signature" << std::endl;
	}
*/	


	
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
ub_privatekey pkey;
pkey.import_private_key("L2LBS5mGLJK4crnMZLpKMTFMCJCCKH33NyY1mg1aXBr64WTZMR1y");
std::string raw_transaction = "020000000181b0b0ad36493b0644196adfcd738647dd9655a798d6f3d04fa0e07033b9ec020100000000ffffffff0200a3e1110000000017a914ebc513241b86490f3fa2522aa0c6d6a219e4c5e28760fe87dc0000000017a9144793bc24aa771ace38743e29c6455a5d8d8e5cdb8700000000";
std::string redeemscript = "552102446a06a4a97a39de16690d8f8cea380cc5466a416b59a6a5ca7d8c3df3440f7221022939d622cb0280fab4fdbd8abac0c583ed9e9db85c5e54b7fa99b09e502d8f0f21036d7cce8ea2f03f695589b6272e6f4b4f85f16ef3725f5e2797ae0830b56d6bf5210277484d6ea40f56175850bd9d6567d1e8bce55beb8932638faa63735aa00d52d221027b9cb70830cbf072fea92c67eac038c4a853f856f5bfc42008c02a79555bf0f52103cd302ee16538438b2a4f23d9f4870ffe11bcb74ea57d6319d1020ef14e7b9a722103250196f0056dde2d0f25e07ec63bafd29148051036d674eadeda04bc9e91046957ae";
auto endorse = create_endorsement_ub(pkey.get_wif_key(), redeemscript, raw_transaction, 0);
std::cout << endorse << std::endl;
	getchar();
	return 0;
}



