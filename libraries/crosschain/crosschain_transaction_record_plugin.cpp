#include <graphene/crosschain/crosschain_transaction_record_plugin.hpp>
#include <graphene/crosschain/crosschain.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/crosschain_trx_object.hpp>
#include <fc/smart_ref_impl.hpp>
#include <fc/thread/thread.hpp>
namespace bpo = boost::program_options;
namespace graphene {
	namespace crosschain {
		using namespace graphene::chain;
		void crosschain_record_plugin::schedule_acquired_record_loop() {
			fc::time_point now = fc::time_point::now();
			int64_t time_to_next_second = 20000000 - (now.time_since_epoch().count() % 20000000);
			if (time_to_next_second < 50000) {    // we must sleep for at least 50ms
				time_to_next_second += 1000000;
			}
			fc::time_point next_wakeup(now + fc::microseconds(time_to_next_second));
			_acquire_crosschain_task = fc::schedule([this] {acquired_crosschain_record_loop(); },
				next_wakeup, "Acquire crosschain record ");
		}
		void crosschain_record_plugin::acquired_crosschain_record_loop() {
			for (const auto& asset_symbol : _asset_symbols) {
				auto& manager = graphene::crosschain::crosschain_manager::get_instance();
				auto hdl = manager.get_crosschain_handle(std::string(asset_symbol));
				//TODO:Change Magic Num to Macro
				std::string multi_sign_account;
				uint32_t return_block_num;
				uint32_t start_num;
				chain::database& db = graphene::chain::database();
				auto& trx_iters = db.get_index_type<graphene::chain::transaction_history_count_index>().indices().get<graphene::chain::by_history_asset_symbol>();
				auto& trx_iter = trx_iters.find(asset_symbol);
				if (trx_iter != trx_iters.end()) {
					start_num = trx_iter->local_count;
				}
				else {
					db.create<crosschain_transaction_history_count_object>([&](crosschain_transaction_history_count_object& obj) {
						obj.asset_symbol = asset_symbol;
						obj.local_count = 0;
					});
					start_num = 0;
				}

				auto pending_trx = hdl->transaction_history(asset_symbol,multi_sign_account, 0, -1, return_block_num);

				auto& last_trx_iters = db.get_index_type<graphene::chain::transaction_history_count_index>().indices().get<graphene::chain::by_history_asset_symbol>();
				auto& last_trx_iter = trx_iters.find(asset_symbol);
				db.modify(*last_trx_iter, [&](crosschain_transaction_history_count_object& obj) { obj.asset_symbol = return_block_num; });


				for (const auto & trx : pending_trx) {
					auto handle_trx = hdl->turn_trx(trx);

					auto& trx_iters = db.get_index_type<graphene::chain::acquired_crosschain_index>().indices().get<graphene::chain::by_acquired_trx_id>();
					auto& trx_iter = trx_iters.find(handle_trx.trx_id);
					if (trx_iter != trx_iters.end()){
						continue;
					}
					db.create<acquired_crosschain_trx_object>([&](acquired_crosschain_trx_object& obj) {
						obj.handle_trx = handle_trx;
						obj.handle_trx_id = handle_trx.trx_id;
						obj.acquired_transaction_state = acquired_trx_uncreate;
					});
				}
			}
			schedule_acquired_record_loop();
		}
		void crosschain_record_plugin::add_acquire_plugin(const std::string& asset_symbol) {
			_asset_symbols.insert(asset_symbol);
		}
		std::string crosschain_record_plugin::plugin_name()const {
			return "crosschain record";
		}

		void crosschain_record_plugin::plugin_set_program_options(
			boost::program_options::options_description &command_line_options,
			boost::program_options::options_description &config_file_options
		) {
			command_line_options.add_options()
				("guard-id,w", bpo::value<vector<string>>()->composing()->multitoken());
			config_file_options.add(command_line_options);
		}
		void crosschain_record_plugin::plugin_initialize(const boost::program_options::variables_map& options){
			try{
				_options = &options;
				LOAD_VALUE_SET(options, "miner-id", _miners, chain::miner_id_type);
				LOAD_VALUE_SET(options, "guard-id", _guard, chain::guard_member_id_type)
			}FC_LOG_AND_RETHROW()
		}
		void crosschain_record_plugin::plugin_startup(){
			if (!_miners.empty() || !_guard.empty()){
				schedule_acquired_record_loop();
			}
			else{
				elog("No miner or guard in this client");
			}
		}
		void crosschain_record_plugin::plugin_shutdown(){
			return;
		}
	}
}