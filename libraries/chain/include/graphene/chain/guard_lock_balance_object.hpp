#pragma once
#include <graphene/chain/protocol/asset.hpp>
#include <graphene/db/object.hpp>
#include <graphene/db/generic_index.hpp>
#include <boost/multi_index/composite_key.hpp>

namespace graphene {
	namespace chain {
		class guard_lock_balance_object;
		class guard_lock_balance_object : public graphene::db::abstract_object<guard_lock_balance_object> {
		public:
			static const uint8_t space_id = protocol_ids;
			static const uint8_t type_id = guard_lock_balance_object_type;
			account_id_type lock_balance_account;
			asset_id_type lock_asset_id;
			share_type lock_asset_amount;

			asset get_lock_balance() const {
				return asset(lock_asset_amount, lock_asset_id);
			}
			
		};
		struct by_guard_lock;
		typedef multi_index_container <
			guard_lock_balance_object,
			indexed_by <
			ordered_unique< tag<by_id>,
			member<object, object_id_type, &object::id>
			>,
			ordered_unique<
			tag<by_guard_lock>,
			composite_key<
			guard_lock_balance_object,
			member<guard_lock_balance_object, account_id_type, &guard_lock_balance_object::lock_balance_account>,
			member<guard_lock_balance_object, asset_id_type, &guard_lock_balance_object::lock_asset_id>
			>,
			composite_key_compare<
			std::less< account_id_type >, 
			std::less< asset_id_type >
			>
			>
			>
		> guard_lock_balance_multi_index_type;
		typedef  generic_index<guard_lock_balance_object, guard_lock_balance_multi_index_type> guard_lock_balance_index;
	}
}

FC_REFLECT_DERIVED(graphene::chain::guard_lock_balance_object, (graphene::db::object),
					(lock_balance_account)
					(lock_asset_id)
					(lock_asset_amount))