#include <graphene/chain/database.hpp>
#include <graphene/chain/pay_back_object.hpp>
#include <graphene/chain/asset_object.hpp>

namespace graphene {
	namespace chain {
		void database::adjust_pay_back_balance(address payback_owner, asset payback_asset) {
			try {
				if (payback_asset.amount == 0) {
					return;
				}
				auto& payback_db = get_index_type<payback_index>().indices().get<by_payback_address>();
				auto itr = payback_db.find(payback_owner);
				auto& asset_db = get_index_type<asset_index>().indices().get<by_id>();
				auto asset_iter = asset_db.find(payback_asset.asset_id);

				FC_ASSERT(asset_iter != asset_db.end(), "this asset doesnt exist");
				std::string asset_symbol = asset_iter->symbol;
				if (itr == payback_db.end()) {
					FC_ASSERT(payback_asset.amount > 0, "lock balance error");
					create<pay_back_object>([payback_owner, payback_asset, asset_symbol](pay_back_object& a) {
						a.owner_balance[asset_symbol] = payback_asset;
						a.pay_back_owner = payback_owner;
					});
				}
				else {
					if (payback_asset.amount < 0) {
						FC_ASSERT((itr->owner_balance.at(asset_symbol) >= -payback_asset), "balance is not enough");
					}
					modify(*itr, [payback_owner, payback_asset, asset_symbol](pay_back_object& b) {
						b.owner_balance[asset_symbol] += payback_asset;
					});
				}
			}FC_CAPTURE_AND_RETHROW((payback_owner)(payback_asset))
		}
		std::vector<asset> database::get_pay_back_balacne(address payback_owner,std::string symbol_type)const {
			try {
				std::vector<asset> results;
				auto& payback_db = get_index_type<payback_index>().indices().get<by_payback_address>();
				auto payback_address_iter = payback_db.find(payback_owner);
				FC_ASSERT((payback_address_iter != payback_db.end()), "this address has no pay back balance");
				if (symbol_type == "") {
					for (const auto& aseet_obj : payback_address_iter->owner_balance) {
						results.push_back(aseet_obj.second);
					}
				}
				else {
					auto symbol_iter = payback_address_iter->owner_balance.find(symbol_type);
					FC_ASSERT((symbol_iter != payback_address_iter->owner_balance.end()), "dont have asset on this symbol");
					results.push_back(symbol_iter->second);
				}
				return results;
			}FC_CAPTURE_AND_RETHROW((payback_owner)(symbol_type))			
		}
	}
}