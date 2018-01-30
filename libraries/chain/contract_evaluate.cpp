#include <graphene/chain/contract_evaluate.hpp>
#include <graphene/chain/contract.hpp>
#include <graphene/chain/storage.hpp>
#include <graphene/chain/contract_entry.hpp>
#include <graphene/chain/contract_engine_builder.hpp>
#include <graphene/chain/uvm_chain_api.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/transaction_object.hpp>

#include <fc/array.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/base58.hpp>
#include <boost/uuid/sha1.hpp>
#include <exception>

namespace graphene {
	namespace chain {

		using uvm::lua::api::global_uvm_chain_api;

		static contract_register_evaluate* get_register_contract_evaluator(lua_State *L) {
			return (contract_register_evaluate*)uvm::lua::lib::get_lua_state_value(L, "register_evaluate_state").pointer_value;
		}

		static contract_invoke_evaluate* get_invoke_contract_evaluator(lua_State *L) {
			return (contract_invoke_evaluate*)uvm::lua::lib::get_lua_state_value(L, "invoke_evaluate_state").pointer_value;
		}

		static contract_upgrade_evaluate* get_upgrade_contract_evaluator(lua_State *L) {
			return (contract_upgrade_evaluate*)uvm::lua::lib::get_lua_state_value(L, "upgrade_evaluate_state").pointer_value;
		}

		static contract_transfer_evaluate* get_contract_transfer_evaluator(lua_State *L) {
			return (contract_transfer_evaluate*)uvm::lua::lib::get_lua_state_value(L, "transfer_evaluate_state").pointer_value;
		}

		StorageDataType common_contract_evaluator::get_storage(const string &contract_id, const string &storage_name) const
		{
			if (register_contract_evaluator)
				return register_contract_evaluator->get_storage(contract_id, storage_name);
			if (register_native_contract_evaluator)
				return register_native_contract_evaluator->get_storage(contract_id, storage_name);
			if (invoke_contract_evaluator)
				return invoke_contract_evaluator->get_storage(contract_id, storage_name);
			if (upgrade_contract_evaluator)
				return upgrade_contract_evaluator->get_storage(contract_id, storage_name);
			if (contract_transfer_evaluator)
				return contract_transfer_evaluator->get_storage(contract_id, storage_name);
			FC_ASSERT(false);
		}

		std::shared_ptr<address> common_contract_evaluator::get_caller_address() const
		{
			if (register_contract_evaluator)
				return register_contract_evaluator->get_caller_address();
			if (register_native_contract_evaluator)
				return register_native_contract_evaluator->get_caller_address();
			if (invoke_contract_evaluator)
				return invoke_contract_evaluator->get_caller_address();
			if (upgrade_contract_evaluator)
				return upgrade_contract_evaluator->get_caller_address();
			if (contract_transfer_evaluator)
				return contract_transfer_evaluator->get_caller_address();
			FC_ASSERT(false);
		}
		std::shared_ptr<fc::ecc::public_key> common_contract_evaluator::get_caller_pubkey() const
		{
			if (register_contract_evaluator)
				return register_contract_evaluator->get_caller_pubkey();
			if (register_native_contract_evaluator)
				return register_native_contract_evaluator->get_caller_pubkey();
			if (invoke_contract_evaluator)
				return invoke_contract_evaluator->get_caller_pubkey();
			if (upgrade_contract_evaluator)
				return upgrade_contract_evaluator->get_caller_pubkey();
			FC_ASSERT(false);
		}
		void common_contract_evaluator::transfer_to_address(const address& contract, const asset & amount, const address & to)
		{
			if (register_contract_evaluator)
				register_contract_evaluator->transfer_to_address(contract, amount, to);
			else if (register_native_contract_evaluator)
				register_native_contract_evaluator->transfer_to_address(contract, amount, to);
			else if (invoke_contract_evaluator)
				invoke_contract_evaluator->transfer_to_address(contract, amount, to);
			else if (upgrade_contract_evaluator)
				upgrade_contract_evaluator->transfer_to_address(contract, amount, to);
			else
				FC_ASSERT(false);
		}

		asset common_contract_evaluator::asset_from_sting(const string& symbol, const string& amount)
		{
			if (register_contract_evaluator)
				return register_contract_evaluator->asset_from_sting(symbol, amount);
			if (register_native_contract_evaluator)
				return register_native_contract_evaluator->asset_from_sting(symbol, amount);
			if (invoke_contract_evaluator)
				return invoke_contract_evaluator->asset_from_sting(symbol, amount);
			if (upgrade_contract_evaluator)
				return upgrade_contract_evaluator->asset_from_sting(symbol, amount);
			FC_ASSERT(false);
		}

		common_contract_evaluator common_contract_evaluator::get_contract_evaluator(lua_State *L) {
			common_contract_evaluator evaluator;
			auto register_contract_evaluator = get_register_contract_evaluator(L);
			if (register_contract_evaluator) {
				evaluator.register_contract_evaluator = register_contract_evaluator;
				return evaluator;
			}
			auto invoke_contract_evaluator = get_invoke_contract_evaluator(L);
			if (invoke_contract_evaluator) {
				evaluator.invoke_contract_evaluator = invoke_contract_evaluator;
				return evaluator;
			}
			auto upgrade_contract_evaluator = get_upgrade_contract_evaluator(L);
			if (upgrade_contract_evaluator) {
				evaluator.upgrade_contract_evaluator = upgrade_contract_evaluator;
				return evaluator;
			}
			auto contract_transfer_evaluator = get_contract_transfer_evaluator(L);
			if (contract_transfer_evaluator) {
				evaluator.contract_transfer_evaluator = contract_transfer_evaluator;
				return evaluator;
			}
			FC_ASSERT(false);
			return evaluator;
		}


		// FIXME: duplicate code

		static share_type count_gas_fee(gas_price_type gas_price, gas_count_type gas_count) {
			// every 100 gas cost 1 min-precision base-asset
			share_type fee = ((gas_count / 100) + ((gas_count % 100) == 0 ? 0 : 1)) * gas_price;
			FC_ASSERT(fee >= 0);
			return fee;
		}

		static share_type count_contract_register_fee(const uvm::blockchain::Code& code) {
			return 10; // contract register fee
		}

		void_result contract_register_evaluate::do_evaluate(const operation_type& o) {
			auto &d = db();
			// check contract id unique
			FC_ASSERT(!d.has_contract(o.contract_id), "contract address must be unique");

			if (!global_uvm_chain_api)
				global_uvm_chain_api = new UvmChainApi();

			this->caller_address = std::make_shared<address>(o.owner_addr);
			this->caller_pubkey = std::make_shared<fc::ecc::public_key>(o.owner_pubkey);
			::blockchain::contract_engine::ContractEngineBuilder builder;
			auto engine = builder.build();
			int exception_code = 0;
			string exception_msg;
			try {
				origin_op = o;
				engine->set_caller(o.owner_pubkey.to_base58(), (string)(o.owner_addr));
				engine->set_state_pointer_value("register_evaluate_state", this);
				engine->clear_exceptions();
				auto limit = o.init_cost;
				if (limit < 0 || limit == 0)
					FC_CAPTURE_AND_THROW(blockchain::contract_engine::uvm_executor_internal_error);

				engine->set_gas_limit(limit);
				contracts_storage_changes.clear();
				try
				{
					engine->execute_contract_init_by_address((string)o.contract_id, "", nullptr);
				}
				catch (uvm::core::UvmException &e)
				{
					throw e; // TODO: change to other error type
				}

				gas_used = engine->gas_used();
				FC_ASSERT(gas_used <= o.init_cost && gas_used > 0, "costs of execution can be only between 0 and init_cost");
				auto register_fee = count_contract_register_fee(o.contract_code);
				auto required = count_gas_fee(o.gas_price, gas_used) + register_fee;

				gas_fees.push_back(asset(required, asset_id_type(0)));
				// TODO: deposit margin balance to contract


                new_contract.contract_address = o.calculate_contract_id();
                new_contract.code = o.contract_code;
                new_contract.owner_address = o.owner_addr;
                new_contract.create_time = o.register_time;

			}
			catch (std::exception &e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (exception_msg));
			}
			catch (::blockchain::contract_engine::contract_run_out_of_money& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_run_out_of_money);
				// TODO: �۳������ṩ�������Ѳ����
			}
			catch (const ::blockchain::contract_engine::contract_error& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_error, (exception_msg));
			}

			return void_result();
		}

		void_result native_contract_register_evaluate::do_evaluate(const operation_type& o) {
			auto &d = db();
			// check contract id unique
			FC_ASSERT(!d.has_contract(o.contract_id), "contract address must be unique");
			this->caller_address = std::make_shared<address>(o.owner_addr);
			this->caller_pubkey = std::make_shared<fc::ecc::public_key>(o.owner_pubkey);
			try {
				FC_ASSERT(native_contract_finder::has_native_contract_with_key(o.native_contract_key));
				common_contract_evaluator evaluator;
				evaluator.register_native_contract_evaluator = this;
				auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, o.native_contract_key, o.contract_id);
				FC_ASSERT(native_contract);
				auto invoke_result = native_contract->invoke("init", "");

				gas_used = 1; // FIXME: native contract exec gas used
				FC_ASSERT(gas_used <= o.init_cost && gas_used > 0, "costs of execution can be only between 0 and init_cost");
				auto register_fee = 1; // FIXME: native contract register fee
				auto required = count_gas_fee(o.gas_price, gas_used) + register_fee;
				gas_fees.push_back(asset(required, asset_id_type(0)));
				// TODO: deposit margin balance to contract

				this->contracts_storage_changes = invoke_result.storage_changes;
				this->invoke_contract_result = invoke_result;

				new_contract.contract_address = o.calculate_contract_id();
				new_contract.is_native_contract = true;
				new_contract.native_contract_key = o.native_contract_key;
				new_contract.owner_address = o.owner_addr;
				new_contract.create_time = o.register_time;

			}
			catch (std::exception &e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
			}
			catch (::blockchain::contract_engine::contract_run_out_of_money& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_run_out_of_money);
				// TODO: �۳������ṩ�������Ѳ����
			}
			catch (const ::blockchain::contract_engine::contract_error& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_error, (e.what()));
			}

			return void_result();
		}

		void_result contract_invoke_evaluate::do_evaluate(const operation_type& o) {
			auto &d = db();
			FC_ASSERT(d.has_contract(o.contract_id));
			auto &contract = d.get_contract(o.contract_id);
			this->caller_address = std::make_shared<address>(o.caller_addr);
			this->caller_pubkey = std::make_shared<fc::ecc::public_key>(o.caller_pubkey);
			try {
				if (contract.is_native_contract)
				{
					FC_ASSERT(native_contract_finder::has_native_contract_with_key(contract.native_contract_key));
					common_contract_evaluator evaluator;
					evaluator.invoke_contract_evaluator = this;
					auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, contract.native_contract_key, o.contract_id);
					FC_ASSERT(native_contract);
					auto invoke_result = native_contract->invoke(o.contract_api, o.contract_arg);
					this->contracts_storage_changes = invoke_result.storage_changes;
					this->invoke_contract_result = invoke_result;
					gas_used = 1; // FIXME: native contract exec gas used
					FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
					auto register_fee = 1; // FIXME: native contract register fee
					auto required = count_gas_fee(o.gas_price, gas_used) + register_fee;
					gas_fees.push_back(asset(required, asset_id_type(0)));
				}
				else
				{
					if (!global_uvm_chain_api)
						global_uvm_chain_api = new UvmChainApi();

					::blockchain::contract_engine::ContractEngineBuilder builder;
					auto engine = builder.build();
					int exception_code = 0;
				
					origin_op = o;
					engine->set_caller(o.caller_pubkey.to_base58(), (string)(o.caller_addr));
					engine->set_state_pointer_value("invoke_evaluate_state", this);
					engine->clear_exceptions();
					auto limit = o.invoke_cost;
					if (limit < 0 || limit == 0)
						FC_CAPTURE_AND_THROW(blockchain::contract_engine::uvm_executor_internal_error);

					engine->set_gas_limit(limit);
					contracts_storage_changes.clear();
					std::string contract_result_str;
					try
					{
						engine->execute_contract_api_by_address((string)o.contract_id, o.contract_api, o.contract_arg, &contract_result_str);
					}
					catch (uvm::core::UvmException &e)
					{
						FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
					}

					gas_used = engine->gas_used();
					FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
					auto required = count_gas_fee(o.gas_price, gas_used);
					// TODO: withdraw required gas fee from owner

				}
			}
			catch (std::exception &e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
			}
			catch (::blockchain::contract_engine::contract_run_out_of_money& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_run_out_of_money);
				// TODO: �۳������ṩ�������Ѳ����
			}
			catch (const ::blockchain::contract_engine::contract_error& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_error, (e.what()));
			}

			return void_result();
		}

		void_result contract_upgrade_evaluate::do_evaluate(const operation_type& o) {
			auto &d = db();
			FC_ASSERT(d.has_contract(o.contract_id));
			FC_ASSERT(!d.has_contract_of_name(o.contract_name));
			auto &contract = d.get_contract(o.contract_id);
			FC_ASSERT(contract.contract_name.empty());
			this->caller_address = std::make_shared<address>(o.caller_addr);
			this->caller_pubkey = std::make_shared<fc::ecc::public_key>(o.caller_pubkey);
			try {
				if (contract.is_native_contract)
				{
					FC_ASSERT(native_contract_finder::has_native_contract_with_key(contract.native_contract_key));
					common_contract_evaluator evaluator;
					evaluator.upgrade_contract_evaluator = this;
					auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, contract.native_contract_key, o.contract_id);
					FC_ASSERT(native_contract);
					auto invoke_result = native_contract->invoke("on_upgrade", o.contract_name);
					this->contracts_storage_changes = invoke_result.storage_changes;
					this->invoke_contract_result = invoke_result;
					gas_used = 1; // FIXME: native contract exec gas used
					FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
					auto register_fee = 1; // FIXME: native contract register fee
					auto required = count_gas_fee(o.gas_price, gas_used) + register_fee;
					gas_fees.push_back(asset(required, asset_id_type(0)));
				}
				else
				{
					if (!global_uvm_chain_api)
						global_uvm_chain_api = new UvmChainApi();

					::blockchain::contract_engine::ContractEngineBuilder builder;
					auto engine = builder.build();
					int exception_code = 0;

					origin_op = o;
					engine->set_caller(o.caller_pubkey.to_base58(), (string)(o.caller_addr));
					engine->set_state_pointer_value("upgrade_evaluate_state", this);
					engine->clear_exceptions();
					auto limit = o.invoke_cost;
					if (limit < 0 || limit == 0)
						FC_CAPTURE_AND_THROW(blockchain::contract_engine::uvm_executor_internal_error);

					engine->set_gas_limit(limit);
					contracts_storage_changes.clear();
					std::string contract_result_str;
					try
					{
						engine->execute_contract_api_by_address((string)o.contract_id, "on_upgrade", o.contract_name, &contract_result_str);
					}
					catch (uvm::core::UvmException &e)
					{
						FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
					}

					gas_used = engine->gas_used();
					FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
					auto required = count_gas_fee(o.gas_price, gas_used);
					gas_fees.push_back(asset(required, asset_id_type(0)));
				}
			}
			catch (std::exception &e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
			}
			catch (::blockchain::contract_engine::contract_run_out_of_money& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_run_out_of_money);
				// TODO: �۳������ṩ�������Ѳ����
			}
			catch (const ::blockchain::contract_engine::contract_error& e)
			{
				FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_error, (e.what()));
			}

			return void_result();
		}

		void_result contract_register_evaluate::do_apply(const operation_type& o) {
			database& d = db();
			// commit contract result to db
			d.store_contract(new_contract);
			auto trx_id = get_current_trx_id();
			for (const auto &pair1 : contracts_storage_changes)
			{
				const auto &contract_id = pair1.first;
				address contract_addr(contract_id);
				const auto &contract_storage_changes = pair1.second;
				for (const auto &pair2 : contract_storage_changes)
				{
					const auto &storage_name = pair2.first;
					const auto &change = pair2.second;
					d.set_contract_storage(contract_addr, storage_name, change.after);
					d.add_contract_storage_change(trx_id, contract_addr, storage_name, change.storage_diff);
				}
			}
			do_apply_contract_event_notifies();
            do_apply_fees_balance(origin_op.owner_addr);
			do_apply_balance();
			return void_result();
		}

		void_result native_contract_register_evaluate::do_apply(const operation_type& o) {
			database& d = db();
			// commit contract result to db
			d.store_contract(new_contract);
			auto trx_id = get_current_trx_id();
			for (const auto &pair1 : contracts_storage_changes)
			{
				const auto &contract_id = pair1.first;
				address contract_addr(contract_id);
				const auto &contract_storage_changes = pair1.second;
				for (const auto &pair2 : contract_storage_changes)
				{
					const auto &storage_name = pair2.first;
					const auto &change = pair2.second;
					d.set_contract_storage(contract_addr, storage_name, change.after);
					d.add_contract_storage_change(trx_id, contract_addr, storage_name, change.storage_diff);
				}
			}
			do_apply_fees_balance(o.owner_addr);
			do_apply_contract_event_notifies();
			return void_result();
		}

		void_result contract_invoke_evaluate::do_apply(const operation_type& o) {
			database& d = db();
			FC_ASSERT(d.has_contract(o.contract_id));
			auto trx_id = get_current_trx_id();
			// commit contract result to db
			for (const auto &pair1 : contracts_storage_changes)
			{
				const auto &contract_id = pair1.first;
				address contract_addr(contract_id);
				const auto &contract_storage_changes = pair1.second;
				for (const auto &pair2 : contract_storage_changes)
				{
					const auto &storage_name = pair2.first;
					const auto &change = pair2.second;
					d.set_contract_storage(contract_addr, storage_name, change.after);
					d.add_contract_storage_change(trx_id, contract_addr, storage_name, change.storage_diff);
				}
			}
			do_apply_contract_event_notifies();
            do_apply_fees_balance(origin_op.caller_addr);
			do_apply_balance();
			return void_result();
		}

		void_result contract_upgrade_evaluate::do_apply(const operation_type& o) {
			database& d = db();
			// save contract name
			FC_ASSERT(d.has_contract(o.contract_id));
			auto& contract = d.get_contract(o.contract_id);
			contract.contract_name = o.contract_name;
			contract.contract_desc = o.contract_desc;
			d.update_contract(contract);
			auto trx_id = get_current_trx_id();
			// commit contract result to db
			for (const auto &pair1 : contracts_storage_changes)
			{
				const auto &contract_id = pair1.first;
				address contract_addr(contract_id);
				const auto &contract_storage_changes = pair1.second;
				for (const auto &pair2 : contract_storage_changes)
				{
					const auto &storage_name = pair2.first;
					const auto &change = pair2.second;
					d.set_contract_storage(contract_addr, storage_name, change.after);
					d.add_contract_storage_change(trx_id, contract_addr, storage_name, change.storage_diff);
				}
			}
			do_apply_contract_event_notifies();
            do_apply_fees_balance(origin_op.caller_addr);
			do_apply_balance();

			return void_result();
		}

		void contract_register_evaluate::pay_fee() {

		}

		void native_contract_register_evaluate::pay_fee() {

		}

		void contract_invoke_evaluate::pay_fee() {

		}

		void contract_upgrade_evaluate::pay_fee() {

		}

		std::shared_ptr<GluaContractInfo> contract_register_evaluate::get_contract_by_id(const string &contract_id) const
		{
			if (string(origin_op.contract_id) == contract_id)
			{
				auto contract_info = std::make_shared<GluaContractInfo>();
				const auto &code = origin_op.contract_code;
				for (const auto & api : code.abi) {
					contract_info->contract_apis.push_back(api);
				}
				return contract_info;
			}
			else
			{
				return nullptr;
			}
		}

		std::shared_ptr<GluaContractInfo> native_contract_register_evaluate::get_contract_by_id(const string &contract_id) const
		{
			if (string(origin_op.contract_id) == contract_id)
			{
				auto contract_info = std::make_shared<GluaContractInfo>();
				common_contract_evaluator evaluator;
				evaluator.register_native_contract_evaluator = const_cast<native_contract_register_evaluate*>(this);
				auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, origin_op.native_contract_key, address(contract_id));
				if (!native_contract)
					return nullptr;
				for (const auto & api : native_contract->apis()) {
					contract_info->contract_apis.push_back(api);
				}
				return contract_info;
			}
			else
			{
				return nullptr;
			}
		}

		contract_object native_contract_register_evaluate::get_contract_by_name(const string& contract_name) const
		{
			FC_ASSERT(!contract_name.empty());
			FC_ASSERT(db().has_contract_of_name(contract_name));
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract_of_name(contract_name);
			// TODO: when contract is native contract
			return contract;
		}

		std::shared_ptr<GluaContractInfo> contract_invoke_evaluate::get_contract_by_id(const string &contract_id) const
		{
			address contract_addr(contract_id);
			if (!db().has_contract(contract_addr))
				return nullptr;
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract(contract_addr);
			if (contract.is_native_contract)
			{
				common_contract_evaluator evaluator;
				evaluator.invoke_contract_evaluator = const_cast<contract_invoke_evaluate*>(this);
				auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, contract.native_contract_key, contract.contract_address);
				if (!native_contract)
					return nullptr;
				for (const auto & api : native_contract->apis()) {
					contract_info->contract_apis.push_back(api);
				}
				return contract_info;
			}
			const auto &code = contract.code;
			for (const auto & api : code.abi) {
				contract_info->contract_apis.push_back(api);
			}
			return contract_info;
		}

		contract_object contract_invoke_evaluate::get_contract_by_name(const string& contract_name) const
		{
			FC_ASSERT(!contract_name.empty());
			FC_ASSERT(db().has_contract_of_name(contract_name));
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract_of_name(contract_name);
			// TODO: when contract is native contract
			return contract;
		}

		// FIXME: duplicate code
		std::shared_ptr<GluaContractInfo> contract_upgrade_evaluate::get_contract_by_id(const string &contract_id) const
		{
			address contract_addr(contract_id);
			if (!db().has_contract(contract_addr))
				return nullptr;
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract(contract_addr);
			if (contract.is_native_contract)
			{
				common_contract_evaluator evaluator;
				evaluator.upgrade_contract_evaluator = const_cast<contract_upgrade_evaluate*>(this);
				auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, contract.native_contract_key, contract.contract_address);
				if (!native_contract)
					return nullptr;
				for (const auto & api : native_contract->apis()) {
					contract_info->contract_apis.push_back(api);
				}
				return contract_info;
			}
			const auto &code = contract.code;
			for (const auto & api : code.abi) {
				contract_info->contract_apis.push_back(api);
			}
			return contract_info;
		}

		contract_object contract_upgrade_evaluate::get_contract_by_name(const string& contract_name) const
		{
			FC_ASSERT(!contract_name.empty());
			FC_ASSERT(db().has_contract_of_name(contract_name));
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract_of_name(contract_name);
			// TODO: when contract is native contract
			return contract;
		}

		contract_object contract_register_evaluate::get_contract_by_name(const string& contract_name) const
		{
			FC_ASSERT(!contract_name.empty());
			FC_ASSERT(db().has_contract_of_name(contract_name));
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract_of_name(contract_name);
			// TODO: when contract is native contract
			return contract;
		}

		std::shared_ptr<uvm::blockchain::Code> contract_register_evaluate::get_contract_code_by_id(const string &contract_id) const
		{
			if (string(origin_op.contract_id) == contract_id)
			{
				auto code = std::make_shared<uvm::blockchain::Code>();
				*code = origin_op.contract_code;
				return code;
			}
			else
			{
				return get_contract_code_from_db_by_id(contract_id);
			}
		}

		std::shared_ptr<uvm::blockchain::Code> contract_invoke_evaluate::get_contract_code_by_id(const string &contract_id) const
		{
			return get_contract_code_from_db_by_id(contract_id);
		}

		// FIXME: duplicate code
		std::shared_ptr<uvm::blockchain::Code> contract_upgrade_evaluate::get_contract_code_by_id(const string &contract_id) const
		{
			address contract_addr(contract_id);
			if (!db().has_contract(contract_addr))
				return nullptr;
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract(contract_addr);
			// TODO: when contract is native contract
			const auto &code = contract.code;
			for (const auto & api : code.abi) {
				contract_info->contract_apis.push_back(api);
			}
			auto ccode = std::make_shared<uvm::blockchain::Code>();
			*ccode = code;
			return ccode;
		}

		address contract_register_evaluate::origin_op_contract_id() const
		{
			return origin_op.contract_id;
		}

		address native_contract_register_evaluate::origin_op_contract_id() const
		{
			return origin_op.contract_id;
		}


        void_result contract_transfer_evaluate::do_evaluate(const operation_type & o)
        {
            auto &d = db();
            FC_ASSERT(d.has_contract(o.contract_id));
            auto &contract = d.get_contract(o.contract_id);
            deposit_to_contract(o.contract_id, o.amount);
            if(contract.code.abi.find("on_deposit")!= contract.code.abi.end())
            {
                try {
                if (contract.is_native_contract)
                {
                    FC_ASSERT(native_contract_finder::has_native_contract_with_key(contract.native_contract_key));
                    common_contract_evaluator evaluator;
                    evaluator.contract_transfer_evaluator = this;
                    auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, contract.native_contract_key, o.contract_id);
                    FC_ASSERT(native_contract);
                    auto invoke_result = native_contract->invoke("on_deposit", fc::json::to_string(o.amount));

                    gas_used = 1; // FIXME: native contract exec gas used
                    FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
                    auto register_fee = 1; // FIXME: native contract register fee
                    auto required = count_gas_fee(o.gas_price, gas_used) + register_fee;
                    gas_fees.push_back(asset(required, asset_id_type(0)));
                }
                else
                {
                    if (!global_uvm_chain_api)
                        global_uvm_chain_api = new UvmChainApi();

                    ::blockchain::contract_engine::ContractEngineBuilder builder;
                    auto engine = builder.build();
                    int exception_code = 0;

                    origin_op = o;
                    engine->set_caller(o.caller_pubkey.to_base58(), (string)(o.caller_addr));
                    engine->set_state_pointer_value("transfer_evaluate_state", this);
                    engine->clear_exceptions();
                    auto limit = o.invoke_cost;
                    if (limit < 0 || limit == 0)
                        FC_CAPTURE_AND_THROW(blockchain::contract_engine::uvm_executor_internal_error);

                    engine->set_gas_limit(limit);
                    contracts_storage_changes.clear();
                    std::string contract_result_str;
                    try
                    {
                        engine->execute_contract_api_by_address((string)o.contract_id, "on_deposit", fc::json::to_string(o.amount), &contract_result_str);
                    }
                    catch (uvm::core::UvmException &e)
                    {
                        FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
                    }

                    gas_used = engine->gas_used();
                    FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
                    auto required = count_gas_fee(o.gas_price, gas_used);
                    // TODO: withdraw required gas fee from owner
                    gas_fees.push_back(required);

                }
            }
            catch (std::exception &e)
            {
                FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
            }
            catch (::blockchain::contract_engine::contract_run_out_of_money& e)
            {
                FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_run_out_of_money);
                // TODO: �۳������ṩ�������Ѳ����
            }
            catch (const ::blockchain::contract_engine::contract_error& e)
            {
                FC_CAPTURE_AND_THROW(::blockchain::contract_engine::contract_error, (e.what()));
            }
        }
            return void_result();
        }

        void_result contract_transfer_evaluate::do_apply(const operation_type & o)
        {
            database& d = db();
            FC_ASSERT(d.has_contract(o.contract_id));
            // commit contract result to db
			auto trx_id = get_current_trx_id();
            for (const auto &pair1 : contracts_storage_changes)
            {
                const auto &contract_id = pair1.first;
                address contract_addr(contract_id);
                const auto &contract_storage_changes = pair1.second;
                for (const auto &pair2 : contract_storage_changes)
                {
                    const auto &storage_name = pair2.first;
                    const auto &change = pair2.second;
                    d.set_contract_storage(contract_addr, storage_name, change.after);
                    d.add_contract_storage_change(trx_id, contract_addr, storage_name, change.storage_diff);
                }
            }

			do_apply_contract_event_notifies();            
			do_apply_fees_balance(o.caller_addr);
            d.adjust_balance(o.caller_addr, asset(0, o.amount.asset_id) - o.amount);
            do_apply_balance();
            return void_result();
        }



        std::shared_ptr<GluaContractInfo> contract_transfer_evaluate::get_contract_by_id(const string & contract_id) const
        {
            address contract_addr(contract_id);
            if (!db().has_contract(contract_addr))
                return nullptr;
            auto contract_info = std::make_shared<GluaContractInfo>();
            const auto &contract = db().get_contract(contract_addr);
            if (contract.is_native_contract)
            {
				common_contract_evaluator evaluator;
				evaluator.contract_transfer_evaluator = const_cast<contract_transfer_evaluate*>(this);
                auto native_contract = native_contract_finder::create_native_contract_by_key(evaluator, contract.native_contract_key, contract.contract_address);
                if (!native_contract)
                    return nullptr;
                for (const auto & api : native_contract->apis()) {
                    contract_info->contract_apis.push_back(api);
                }
                return contract_info;
            }
            const auto &code = contract.code;
            for (const auto & api : code.abi) {
                contract_info->contract_apis.push_back(api);
            }
            return contract_info;
        }

        contract_object contract_transfer_evaluate::get_contract_by_name(const string & contract_name) const
        {
            FC_ASSERT(!contract_name.empty());
            FC_ASSERT(db().has_contract_of_name(contract_name));
            auto contract_info = std::make_shared<GluaContractInfo>();
            const auto &contract = db().get_contract_of_name(contract_name);
            // TODO: when contract is native contract
            return contract;
        }

        std::shared_ptr<uvm::blockchain::Code> contract_transfer_evaluate::get_contract_code_by_id(const string & contract_id) const
        {
            return get_contract_code_from_db_by_id(contract_id);
        }
}
}
