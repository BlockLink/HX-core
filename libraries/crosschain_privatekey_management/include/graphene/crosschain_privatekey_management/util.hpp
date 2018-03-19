/**
* Author: wengqiang (email: wens.wq@gmail.com  site: qiangweng.site)
*
* Copyright © 2015--2018 . All rights reserved.
*
* File: util.hpp
* Date: 2018-03-19
*/

#pragma once

#include <graphene/crosschain_privatekey_management/private_key.hpp>
#include <bitcoin/bitcoin.hpp>

#include <assert.h>

namespace graphene {
    namespace privatekey_management {

        std::string get_address_by_pubkey(const std::string& pubkey_hex_str, uint8_t version);

    }


}

