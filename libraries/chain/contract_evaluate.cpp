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
				catch (uvm::core::GluaException &e)
				{
					throw e; // TODO: change to other error type
				}

				gas_used = engine->gas_used();
				FC_ASSERT(gas_used <= o.init_cost && gas_used > 0, "costs of execution can be only between 0 and init_cost");
				auto register_fee = count_contract_register_fee(o.contract_code);
				auto required = count_gas_fee(o.gas_price, gas_used) + register_fee;

				// TODO: withdraw from owner and deposit margin balance to contract


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

		void_result contract_invoke_evaluate::do_evaluate(const operation_type& o) {

			if (!global_uvm_chain_api)
				global_uvm_chain_api = new UvmChainApi();

			::blockchain::contract_engine::ContractEngineBuilder builder;
			auto engine = builder.build();
			int exception_code = 0;
			string exception_msg;
			try {

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
				catch (uvm::core::GluaException &e)
				{
					FC_CAPTURE_AND_THROW(::blockchain::contract_engine::uvm_executor_internal_error, (e.what()));
				}

				gas_used = engine->gas_used();
				FC_ASSERT(gas_used <= o.invoke_cost && gas_used > 0, "costs of execution can be only between 0 and invoke_cost");
				auto required = count_gas_fee(o.gas_price, gas_used);
				// TODO: withdraw required gas fee from owner

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

		void_result contract_register_evaluate::do_apply(const operation_type& o) {
			database& d = db();
			// commit contract result to db
			auto new_contract_addr = string(new_contract.contract_address);
			// if is new_contract storage change, put it directly, and add storage change diff
			for (const auto &pair1 : contracts_storage_changes)
			{
				const auto &contract_id = pair1.first;
				if (contract_id != new_contract_addr) {
					continue;
				}
				address contract_addr(contract_id);
				const auto &contract_storage_changes = pair1.second;
				for (const auto &pair2 : contract_storage_changes)
				{
					const auto &storage_name = pair2.first;
					const auto &change = pair2.second;
					new_contract.storages[storage_name] = change.after.storage_data;
					d.add_contract_storage_change(contract_addr, storage_name, change.storage_diff);
				}
			}
			/*if (d.has_contract(new_contract.contract_address))
			{
				// FIXME: �־û�Ӧ��ֻ�ڿ�������ʱִ��
				return void_result();;
			}*/
			d.store_contract(new_contract);
			
			for (const auto &pair1 : contracts_storage_changes)
			{
				const auto &contract_id = pair1.first;
				address contract_addr(contract_id);
				const auto &contract_storage_changes = pair1.second;
				for (const auto &pair2 : contract_storage_changes)
				{
					const auto &storage_name = pair2.first;
					const auto &change = pair2.second;
					if (contract_id == new_contract_addr) {
						continue;
					}
					else {
						d.set_contract_storage(contract_addr, storage_name, change.after);
					}
					d.add_contract_storage_change(contract_addr, storage_name, change.storage_diff);
				}
			}
			return void_result();
		}

		void_result contract_invoke_evaluate::do_apply(const operation_type& o) {
			database& d = db();
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
					d.add_contract_storage_change(contract_addr, storage_name, change.storage_diff);
				}
			}
			return void_result();
		}

		void contract_register_evaluate::pay_fee() {

		}

		void contract_invoke_evaluate::pay_fee() {

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

		std::shared_ptr<GluaContractInfo> contract_invoke_evaluate::get_contract_by_id(const string &contract_id) const
		{
			address contract_addr(contract_id);
			if (!db().has_contract(contract_addr))
				return nullptr;
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract(contract_addr);
			const auto &code = contract.code;
			for (const auto & api : code.abi) {
				contract_info->contract_apis.push_back(api);
			}
			return contract_info;
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
				return nullptr;
			}
		}

		std::shared_ptr<uvm::blockchain::Code> contract_invoke_evaluate::get_contract_code_by_id(const string &contract_id) const
		{
			address contract_addr(contract_id);
			if (!db().has_contract(contract_addr))
				return nullptr;
			auto contract_info = std::make_shared<GluaContractInfo>();
			const auto &contract = db().get_contract(contract_addr);
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

		StorageDataType contract_register_evaluate::get_storage(const string &contract_id, const string &storage_name) const
		{
			database& d = db();
			auto storage_data = d.get_contract_storage(address(contract_id), storage_name);
			return storage_data;
		}

		StorageDataType contract_invoke_evaluate::get_storage(const string &contract_id, const string &storage_name) const
		{
			database& d = db();
			auto storage_data = d.get_contract_storage(address(contract_id), storage_name);
			return storage_data;
		}

	}
}
