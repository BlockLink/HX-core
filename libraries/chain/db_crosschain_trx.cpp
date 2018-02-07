#include <graphene/chain/database.hpp>
#include <graphene/chain/crosschain_trx_object.hpp>
namespace graphene {
	namespace chain {
		void database::adjust_deposit_to_link_trx(const hd_trx& handled_trx) {
			try {
				auto & deposit_db = get_index_type<acquired_crosschain_index>().indices().get<by_acquired_trx_id>();
				auto deposit_to_link_trx = deposit_db.find(handled_trx.trx_id);
				if (deposit_to_link_trx == deposit_db.end()) {
					create<acquired_crosschain_trx_object>([&](acquired_crosschain_trx_object& obj) {
						obj.handle_trx = handled_trx;
						obj.handle_trx_id = handled_trx.trx_id;
						obj.acquired_transaction_state = acquired_trx_create;
					});
				}
				else {
					if (deposit_to_link_trx->acquired_transaction_state != acquired_trx_uncreate) {
						FC_ASSERT("deposit transaction exist");
					}
					modify(*deposit_to_link_trx, [&](acquired_crosschain_trx_object& obj) {
						obj.acquired_transaction_state = acquired_trx_create;
					});
				}

			}FC_CAPTURE_AND_RETHROW((handled_trx))
		}
		void database::adjust_crosschain_confirm_trx(const hd_trx& handled_trx) {
			try {
				auto & deposit_db = get_index_type<acquired_crosschain_index>().indices().get<by_acquired_trx_id>();
				auto deposit_to_link_trx = deposit_db.find(handled_trx.trx_id);
				if (deposit_to_link_trx == deposit_db.end()) {
					create<acquired_crosschain_trx_object>([&](acquired_crosschain_trx_object& obj) {
						obj.handle_trx = handled_trx;
						obj.handle_trx_id = handled_trx.trx_id;
						obj.acquired_transaction_state = acquired_trx_comfirmed;
					});
				}
				else {
					if (deposit_to_link_trx->acquired_transaction_state != acquired_trx_uncreate) {
						FC_ASSERT("deposit transaction exist");
					}
					modify(*deposit_to_link_trx, [&](acquired_crosschain_trx_object& obj) {
						obj.acquired_transaction_state = acquired_trx_comfirmed;
					});
				}

			}FC_CAPTURE_AND_RETHROW((handled_trx))
		}

		
		void database::adjust_crosschain_transaction(transaction_id_type relate_transaction_id,
			transaction_id_type transaction_id,
			signed_transaction real_transaction,
			uint64_t op_type,
			transaction_stata trx_state,
			vector<transaction_id_type> relate_transaction_ids
		) {

			try {
				if (op_type == operation::tag<crosschain_withdraw_evaluate::operation_type>::value) {
					auto& trx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_itr = trx_db.find(transaction_id);
					FC_ASSERT(trx_itr == trx_db.end(), "This Transaction exist");
					create<crosschain_trx_object>([&](crosschain_trx_object& obj) {
						obj.op_type = op_type;
						obj.relate_transaction_id = transaction_id_type();
						obj.transaction_id = transaction_id;
						obj.real_transaction = real_transaction;
						obj.trx_state = withdraw_without_sign_trx_uncreate;
					});
				}
				else if (op_type == operation::tag<crosschain_withdraw_without_sign_evaluate::operation_type>::value) {
					auto& trx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_itr = trx_db.find(relate_transaction_id);
					FC_ASSERT(trx_itr != trx_db.end(), "Source Transaction doesn`t exist");
					auto& trx_db_relate = get_index_type<crosschain_trx_index>().indices().get<by_relate_trx_id>();
					auto trx_itr_relate = trx_db_relate.find(transaction_id);
					FC_ASSERT(trx_itr_relate == trx_db_relate.end(), "Crosschain transaction has been created");

					auto& trx_db_new = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_iter_new = trx_db_new.find(relate_transaction_id);
					std::cout << relate_transaction_id.str() << std::endl;
					std::cout << (trx_iter_new == trx_db_new.end()) << std::endl;
					modify(*trx_iter_new, [&](crosschain_trx_object& obj) {
						obj.trx_state = withdraw_without_sign_trx_create;
					});

					create<crosschain_trx_object>([&](crosschain_trx_object& obj) {
						obj.op_type = op_type;
						obj.relate_transaction_id = relate_transaction_id;
						obj.real_transaction = real_transaction;
						obj.transaction_id = transaction_id;
						obj.all_related_origin_transaction_ids = relate_transaction_ids;
						obj.trx_state = withdraw_without_sign_trx_create;
					});
					std::cout << "Run modify2" << std::endl;
				}
				else if (op_type == operation::tag<crosschain_withdraw_combine_sign_evaluate::operation_type>::value) {
					auto& trx_db_relate = get_index_type<crosschain_trx_index>().indices().get<by_relate_trx_id>();
					auto trx_itr_relate = trx_db_relate.find(relate_transaction_id);
					FC_ASSERT(trx_itr_relate != trx_db_relate.end(), "Source trx doesnt exist");

					auto& trx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_itr = trx_db.find(transaction_id);
					FC_ASSERT(trx_itr == trx_db.end(), "This sign tex is exist");
					create<crosschain_trx_object>([&](crosschain_trx_object& obj) {
						obj.op_type = op_type;
						obj.relate_transaction_id = relate_transaction_id;
						obj.real_transaction = real_transaction;
						obj.transaction_id = transaction_id;
						obj.trx_state = withdraw_combine_trx_create;
					});
					auto& trx_db_new = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_iter_new = trx_db_new.find(relate_transaction_id);
					modify(*trx_iter_new, [&](crosschain_trx_object& obj) {
						obj.trx_state = withdraw_combine_trx_create;
					});
					vector<transaction_id_type> withsign_trxs;
					get_index_type<crosschain_trx_index>().inspect_all_objects([&](const object& o)
					{
						const crosschain_trx_object& p = static_cast<const crosschain_trx_object&>(o);
						if (p.trx_state == withdraw_sign_trx && p.relate_transaction_id == relate_transaction_id) {
							withsign_trxs.push_back(p.relate_transaction_id);
						}
					});
					for (auto withsign_trx : withsign_trxs) {
						auto& sign_tx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
						auto sign_tx_iter = sign_tx_db.find(withsign_trx);
						modify(*sign_tx_iter, [&](crosschain_trx_object& obj) {
							obj.trx_state = withdraw_combine_trx_create;
						});
					}
				}
				else if (op_type == operation::tag<crosschain_withdraw_with_sign_evaluate::operation_type>::value) {
					auto& trx_db_relate = get_index_type<crosschain_trx_index>().indices().get<by_relate_trx_id>();
					auto trx_itr_relate = trx_db_relate.find(relate_transaction_id);
					FC_ASSERT(trx_itr_relate != trx_db_relate.end(), "Source trx doesnt exist");

					auto& trx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_itr = trx_db.find(transaction_id);
					FC_ASSERT(trx_itr == trx_db.end(), "This sign tex is exist");
					create<crosschain_trx_object>([&](crosschain_trx_object& obj) {
						obj.op_type = op_type;
						obj.relate_transaction_id = relate_transaction_id;
						obj.real_transaction = real_transaction;
						obj.transaction_id = transaction_id;
						obj.trx_state = withdraw_sign_trx;
					});
				}
				else if (op_type == operation::tag<crosschain_withdraw_result_evaluate::operation_type>::value) {
					auto& trx_db_relate = get_index_type<crosschain_trx_index>().indices().get<by_relate_trx_id>();
					auto trx_itr_relate = trx_db_relate.find(relate_transaction_id);
					FC_ASSERT(trx_itr_relate != trx_db_relate.end(), "Source trx doesnt exist");

					auto& trx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_itr = trx_db.find(transaction_id);
					FC_ASSERT(trx_itr != trx_db.end(), "crosschain trx doesnt exist on link");
					modify(*trx_itr, [&](crosschain_trx_object& obj) {
						obj.trx_state = withdraw_transaction_confirm;
					});
					auto& trx_db_new = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					auto trx_iter_new = trx_db_new.find(relate_transaction_id);
					modify(*trx_iter_new, [&](crosschain_trx_object& obj) {
						obj.trx_state = withdraw_transaction_confirm;
					});
					vector<transaction_id_type> withsign_trxs;
					get_index_type<crosschain_trx_index>().inspect_all_objects([&](const object& o)
					{
						const crosschain_trx_object& p = static_cast<const crosschain_trx_object&>(o);
						if (p.trx_state == withdraw_combine_trx_create && p.relate_transaction_id == relate_transaction_id) {
							withsign_trxs.push_back(p.relate_transaction_id);
						}
					});
					for (auto withsign_trx : withsign_trxs) {
						auto& sign_tx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
						auto sign_tx_iter = sign_tx_db.find(withsign_trx);
						modify(*sign_tx_iter, [&](crosschain_trx_object& obj) {
							obj.trx_state = withdraw_transaction_confirm;
						});
					}
				}
			}FC_CAPTURE_AND_RETHROW((relate_transaction_id)(transaction_id))
		}
		void database::create_result_transaction(miner_id_type miner, fc::ecc::private_key pk) {
			vector<crosschain_trx_object> create_withdraw_trx;
			get_index_type<crosschain_trx_index>().inspect_all_objects([&](const object& o)
			{
				const crosschain_trx_object& p = static_cast<const crosschain_trx_object&>(o);
				if (p.trx_state == withdraw_without_sign_trx_uncreate){
					create_withdraw_trx.push_back(p);
				}
			});
			std::map<asset_id_type, std::map<std::string, std::string>> dest_info;
			std::map<std::string, std::string> memo_info;
			std::map<std::string, vector<transaction_id_type>> ccw_trx_ids;
			for (auto & cross_chain_trx : create_withdraw_trx){
				if (cross_chain_trx.real_transaction.id() != cross_chain_trx.transaction_id || cross_chain_trx.real_transaction.operations.size() < 1){
					continue;
				}
				auto op = cross_chain_trx.real_transaction.operations[0];
				auto withop = op.get<crosschain_withdraw_evaluate::operation_type>();
				std::map<std::string, std::string> temp_map;
				std::vector<transaction_id_type> temp_vector;
				if (dest_info.count(withop.asset_id)>0)
				{
					temp_map = dest_info[withop.asset_id];
					temp_vector = ccw_trx_ids[withop.asset_symbol];
				}
				if (temp_map.count(withop.crosschain_account)>0)
				{
					temp_map[withop.crosschain_account] = fc::to_string(to_double(temp_map[withop.crosschain_account]) + to_double(withop.amount)).c_str();
					
				}
				else
				{
					temp_map[withop.crosschain_account] = withop.amount;
				}
				temp_vector.push_back(cross_chain_trx.real_transaction.id());
				dest_info[withop.asset_id] = temp_map;
				ccw_trx_ids[withop.asset_symbol] = temp_vector;

				
				memo_info[withop.asset_symbol] = withop.memo;
			}

			for (auto& one_asset : dest_info)
			{
				auto& manager = graphene::crosschain::crosschain_manager::get_instance();
				optional<asset_object> opt_asset= get(one_asset.first);
				if (!opt_asset.valid())
				{
					continue;
				}
				auto asset_symbol = opt_asset->symbol;
				auto hdl = manager.get_crosschain_handle(std::string(asset_symbol));
				crosschain_withdraw_without_sign_operation trx_op;
				multisig_account_pair_object multi_account_obj;

				get_index_type<multisig_account_pair_index >().inspect_all_objects([&](const object& o)
				{
					const multisig_account_pair_object& p = static_cast<const multisig_account_pair_object&>(o);
					if (p.chain_type == asset_symbol) {
						if (multi_account_obj.effective_block_num < p.effective_block_num && p.effective_block_num <= head_block_num()) {
							multi_account_obj = p;
						}
					}
				});
				//auto multisign_hot = multisign_db.find()
				FC_ASSERT(multi_account_obj.bind_account_cold != multi_account_obj.bind_account_hot);
				/*std::map<const std::string, const std::string> temp_map;
				for (auto & itr : one_asset.second)
				{
					const std::string key = itr.first;
					const std::string value = itr.second;
					temp_map.insert(std::make_pair(key,value));
				}*/
				trx_op.withdraw_source_trx = hdl->create_multisig_transaction(multi_account_obj.bind_account_hot, one_asset.second, asset_symbol, memo_info[asset_symbol], false);
				trx_op.ccw_trx_ids = ccw_trx_ids[asset_symbol];
				//std::cout << trx_op.ccw_trx_id.str() << std::endl;
				trx_op.miner_broadcast = miner;
				trx_op.asset_symbol = asset_symbol;
				trx_op.asset_id = opt_asset->id;
				optional<miner_object> miner_iter = get(miner);
				optional<account_object> account_iter = get(miner_iter->miner_account);
				trx_op.miner_address = account_iter->addr;
				signed_transaction tx;

				uint32_t expiration_time_offset = 0;
				auto dyn_props = get_dynamic_global_properties();
// 				operation temp = operation(op);
 				get_global_properties().parameters.current_fees->set_fee((operation)trx_op);
				tx.set_reference_block(dyn_props.head_block_id);
				tx.set_expiration(dyn_props.time + fc::seconds(30 + expiration_time_offset));
				tx.operations.push_back(trx_op);
				tx.validate();
				tx.sign(pk, get_chain_id());
				push_transaction(tx);
			}
			
			
		}
		void database::create_acquire_crosschhain_transaction(miner_id_type miner, fc::ecc::private_key pk){
			map<string, vector<acquired_crosschain_trx_object>> acquired_crosschain_trx;
			get_index_type<acquired_crosschain_index>().inspect_all_objects([&](const object& o){
				const acquired_crosschain_trx_object& p = static_cast<const acquired_crosschain_trx_object&>(o);
				if (p.acquired_transaction_state == acquired_trx_uncreate){
					acquired_crosschain_trx[p.handle_trx.asset_symbol].push_back(p);
				}
			});

			for (auto & acquired_trxs : acquired_crosschain_trx) {
				auto& manager = graphene::crosschain::crosschain_manager::get_instance();
				auto hdl = manager.get_crosschain_handle(acquired_trxs.first);
				set<string> multi_account_obj_hot;
				get_index_type<multisig_account_pair_index >().inspect_all_objects([&](const object& o)
				{
					const multisig_account_pair_object& p = static_cast<const multisig_account_pair_object&>(o);
					if (p.chain_type == acquired_trxs.first) {
						multi_account_obj_hot.insert(p.bind_account_hot);
					}
				});
				for (auto acquired_trx : acquired_trxs.second){
					auto to_intr = multi_account_obj_hot.find(acquired_trx.handle_trx.to_account);
					auto from_iter = multi_account_obj_hot.find(acquired_trx.handle_trx.from_account);
					if (to_intr != multi_account_obj_hot.end()){
						crosschain_record_operation op;
						auto & asset_iter = get_index_type<asset_index>().indices().get<by_symbol>();
						auto asset_itr = asset_iter.find(acquired_trx.handle_trx.asset_symbol);
						if (asset_itr == asset_iter.end()) {
							continue;
						}
						op.asset_id = asset_itr->id;
						op.asset_symbol = acquired_trx.handle_trx.asset_symbol;
						op.cross_chain_trx = acquired_trx.handle_trx;
						op.miner_broadcast = miner;
						optional<miner_object> miner_iter = get(miner);
						optional<account_object> account_iter = get(miner_iter->miner_account);
						op.miner_address = account_iter->addr;
						signed_transaction tx;
						uint32_t expiration_time_offset = 0;
						auto dyn_props = get_dynamic_global_properties();
						operation temp = operation(op);
                                                get_global_properties().parameters.current_fees->set_fee(temp);
                                                tx.set_reference_block(dyn_props.head_block_id);
						tx.set_expiration(dyn_props.time + fc::seconds(30 + expiration_time_offset));
						tx.operations.push_back(op);
						tx.validate();
						tx.sign(pk, get_chain_id());
						push_transaction(tx);
					}
					else if(from_iter != multi_account_obj_hot.end()){
						crosschain_withdraw_result_operation op;
						op.cross_chain_trx = acquired_trx.handle_trx;
						op.miner_broadcast = miner;
						optional<miner_object> miner_iter = get(miner);
						optional<account_object> account_iter = get(miner_iter->miner_account);
						op.miner_address = account_iter->addr;
						signed_transaction tx;
						uint32_t expiration_time_offset = 0;
						auto dyn_props = get_dynamic_global_properties();
                                                operation temp = operation(op);
						get_global_properties().parameters.current_fees->set_fee(temp);
						tx.set_reference_block(dyn_props.head_block_id);
						tx.set_expiration(dyn_props.time + fc::seconds(30 + expiration_time_offset));
						tx.operations.push_back(op);
						tx.validate();
						tx.sign(pk, get_chain_id());
						push_transaction(tx);
					}
				}
			}
		}
		void database::combine_sign_transaction(miner_id_type miner, fc::ecc::private_key pk) {
			try {
				map<transaction_id_type, vector<transaction_id_type>> uncombine_trxs_counts;
				get_index_type<crosschain_trx_index >().inspect_all_objects([&](const object& o)
				{
					const crosschain_trx_object& p = static_cast<const crosschain_trx_object&>(o);
					if (p.trx_state == withdraw_sign_trx && p.relate_transaction_id != transaction_id_type()) {
						uncombine_trxs_counts[p.relate_transaction_id].push_back(p.transaction_id);
					}
				});
				for (auto & trxs : uncombine_trxs_counts) {
					//TODO : Use macro instead this magic number
					if (trxs.second.size() < ceil(float(get_global_properties().active_committee_members.size())*2.0/3.0)) {
						continue;
					}
					set<string> combine_signature;
					auto& trx_db = get_index_type<crosschain_trx_index>().indices().get<by_transaction_id>();
					bool transaction_err = false;
					for (auto & sign_trx_id : trxs.second) {
						auto trx_itr = trx_db.find(sign_trx_id);

						if (trx_itr == trx_db.end() || trx_itr->real_transaction.operations.size() < 1) {
							transaction_err = true;
							break;
						}
						auto op = trx_itr->real_transaction.operations[0];
						if (op.which() != operation::tag<crosschain_withdraw_with_sign_evaluate::operation_type>::value)
						{
							continue;
						}
						auto with_sign_op = op.get<crosschain_withdraw_with_sign_evaluate::operation_type>();
						combine_signature.insert(with_sign_op.ccw_trx_signature);
					}
					if (transaction_err) {
						continue;
					}
					auto& trx_new_db = get_index_type<crosschain_trx_index>().indices().get<by_trx_relate_type_stata>();
					auto trx_itr = trx_new_db.find(boost::make_tuple(trxs.first, withdraw_without_sign_trx_create));
					if (trx_itr == trx_new_db.end() || trx_itr->real_transaction.operations.size() < 1) {
						continue;
					}
					auto op = trx_itr->real_transaction.operations[0];
					auto with_sign_op = op.get<crosschain_withdraw_without_sign_evaluate::operation_type>();
					auto& manager = graphene::crosschain::crosschain_manager::get_instance();
					auto hdl = manager.get_crosschain_handle(std::string(with_sign_op.asset_symbol));
					crosschain_withdraw_combine_sign_operation trx_op;
					vector<string> guard_signed(combine_signature.begin(), combine_signature.end());
					trx_op.cross_chain_trx = hdl->merge_multisig_transaction(with_sign_op.withdraw_source_trx, guard_signed);
					trx_op.asset_symbol = with_sign_op.asset_symbol;
					trx_op.signed_trx_ids.swap(trxs.second);
					trx_op.miner_broadcast = miner;
					optional<miner_object> miner_iter = get(miner);
					optional<account_object> account_iter = get(miner_iter->miner_account);
					trx_op.miner_address = account_iter->addr;
					trx_op.withdraw_trx = trx_itr->real_transaction.id();
					signed_transaction tx;
					uint32_t expiration_time_offset = 0;
					auto dyn_props = get_dynamic_global_properties();
					operation temp = operation(op);
                                        get_global_properties().parameters.current_fees->set_fee(temp);
                                        tx.set_reference_block(dyn_props.head_block_id);
					tx.set_expiration(dyn_props.time + fc::seconds(30 + expiration_time_offset));
					tx.operations.push_back(trx_op);
					tx.validate();
					tx.sign(pk, get_chain_id());
					push_transaction(tx);
				}
			}FC_CAPTURE_AND_LOG((0))
		}
	}
}
