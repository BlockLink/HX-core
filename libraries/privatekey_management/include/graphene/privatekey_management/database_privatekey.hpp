﻿/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: database_privatekey.hpp
* Date: 2018-01-11
*/


#pragma once

#include "fc/filesystem.hpp"
#include "fc/optional.hpp"
#include "fc/crypto/sha512.hpp"
#include "graphene/privatekey_management/private_key.hpp"

#include <fstream>
#include <string>
#include <vector>

namespace graphene {
	namespace privatekey_management {

		struct crosschain_privatekey_data
		{
			uint64_t        id;
			std::string     addr;
			std::string     wif_key;

		};

		struct crosschain_privatekey_store
		{
			uint64_t            id;

			/** address */
			std::string         addr;

			/** encrypted keys */
			std::vector<char>   cipher_keys;

		};

		
		class database_privatekey
		{
		public:
			void open(const fc::path& dbdir);
			bool is_open()const;
			void flush();
			void close();


			void store(const crosschain_privatekey_data& key_data, fc::sha512  checksum);
			void remove(const crosschain_privatekey_data& key_data);

			bool contains(const uint64_t key_id)const;

			fc::optional<crosschain_privatekey_data> fetch_by_id(const uint64_t key_id, fc::sha512 checksum)const;


		private:
			mutable std::fstream _keys;
			mutable std::fstream _key_index;

		};



	}
} // end namespace graphene::privatekey_management

