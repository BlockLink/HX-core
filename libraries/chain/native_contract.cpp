#include <graphene/chain/native_contract.hpp>
#include <graphene/chain/contract_evaluate.hpp>

#include <boost/algorithm/string.hpp>

namespace graphene {
	namespace chain {
		// TODO: more native contracts
		// TODO: balance and storage changes in native contracts

		void abstract_native_contract::set_contract_storage(const address& contract_address, const string& storage_name, const StorageDataType& value)
		{
			if (_contract_invoke_result.storage_changes.find(string(contract_address)) == _contract_invoke_result.storage_changes.end())
			{
				_contract_invoke_result.storage_changes[string(contract_address)] = std::unordered_map<std::string, StorageDataChangeType>();
			}
			auto& storage_changes = _contract_invoke_result.storage_changes[string(contract_address)];
			if (storage_changes.find(storage_name) == storage_changes.end())
			{
				StorageDataChangeType change;
				change.after = value;
				const auto &before = _evaluate.get_storage(string(contract_address), storage_name);
				jsondiff::JsonDiff differ;
				auto before_json_str = before.as<string>();
				auto after_json_str = change.after.as<string>();
				auto diff = differ.diff_by_string(before_json_str, after_json_str);
				change.storage_diff = jsondiff::json_dumps(diff->value());
				storage_changes[storage_name] = change;
			}
			else
			{
				auto& change = storage_changes[storage_name];
				auto before = change.after;
				auto after = value;
				change.after = after;
				jsondiff::JsonDiff differ;
				auto before_json_str = before.as<string>();
				auto after_json_str = after.as<string>();
				auto diff = differ.diff_by_string(before_json_str, after_json_str);
				change.storage_diff = jsondiff::json_dumps(diff->value());
			}
		}
		StorageDataType abstract_native_contract::get_contract_storage(const address& contract_address, const string& storage_name)
		{
			if (_contract_invoke_result.storage_changes.find(string(contract_address)) == _contract_invoke_result.storage_changes.end())
			{
				return _evaluate.get_storage(string(contract_address), storage_name);
			}
			std::unordered_map<std::string, StorageDataChangeType>& storage_changes = _contract_invoke_result.storage_changes[string(contract_address)];
			if (storage_changes.find(storage_name) == storage_changes.end())
			{
				return _evaluate.get_storage(string(contract_address), storage_name);
			}
			return storage_changes[storage_name].after;
		}

		std::string demo_native_contract::contract_key() const
		{
			return demo_native_contract::native_contract_key();
		}
		address demo_native_contract::contract_address() const {
			return contract_id;
		}
		std::set<std::string> demo_native_contract::apis() const {
			return { "init", "hello" };
		}
		std::set<std::string> demo_native_contract::offline_apis() const {
			return {};
		}
		std::set<std::string> demo_native_contract::events() const {
			return {};
		}

		contract_invoke_result demo_native_contract::invoke(const std::string& api_name, const std::string& api_arg) {
			contract_invoke_result result;
			printf("demo native contract called\n");
			printf("api %s called with arg %s\n", api_name.c_str(), api_arg.c_str());
			return result;
		}

		// token contract
		std::string token_native_contract::contract_key() const
		{
			return token_native_contract::native_contract_key();
		}
		address token_native_contract::contract_address() const {
			return contract_id;
		}
		std::set<std::string> token_native_contract::apis() const {
			return { "init", "init_token", "transfer", "transferFrom", "balanceOf", "approve", "approvedBalanceFrom", "allApprovedFromUser", "state", "supply", "precision" };
		}
		std::set<std::string> token_native_contract::offline_apis() const {
			return { "balanceOf", "approvedBalanceFrom", "allApprovedFromUser", "state", "supply", "precision" };
		}
		std::set<std::string> token_native_contract::events() const {
			return { "Inited", "Transfer", "Approved" };
		}

		static const string not_inited_state_of_token_contract = "NOT_INITED";

		contract_invoke_result token_native_contract::init_api(const std::string& api_name, const std::string& api_arg)
		{
			set_contract_storage(contract_id, string("name"), string("\"\""));
			set_contract_storage(contract_id, string("supply"), string("0"));
			set_contract_storage(contract_id, string("precision"), string("0"));
			set_contract_storage(contract_id, string("users"), string("{}"));
			set_contract_storage(contract_id, string("allowed"), string("{}"));
			set_contract_storage(contract_id, string("state"), string("\"") + not_inited_state_of_token_contract + "\"");
			auto caller_addr = _evaluate.get_caller_address();
			FC_ASSERT(caller_addr);
			set_contract_storage(contract_id, string("admin"), jsondiff::json_dumps(string(*caller_addr)));
			set_contract_storage(contract_id, string("users"), string("{}"));
			return _contract_invoke_result;
		}

		string token_native_contract::check_admin()
		{
			auto caller_addr = _evaluate.get_caller_address();
			if (!caller_addr)
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "only admin can call this api");
			auto admin_storage = get_contract_storage(contract_id, string("admin"));
			auto admin = jsondiff::json_loads(admin_storage.as<string>());
			if (admin.is_string() && admin.as_string() == string(*caller_addr))
				return admin.as_string();
			FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "only admin can call this api");
		}

		string token_native_contract::get_storage_state()
		{
			auto state_storage = get_contract_storage(contract_id, string("state"));
			auto state = jsondiff::json_loads(state_storage.as<string>());
			return state.as_string();
		}

		static bool is_numeric(std::string number)
		{
			char* end = 0;
			std::strtod(number.c_str(), &end);

			return end != 0 && *end == 0;
		}


		static bool is_integral(std::string number)
		{
			return is_numeric(number.c_str()) && std::strchr(number.c_str(), '.') == 0;
		}

		// arg format: name,symbol,supply,precision
		contract_invoke_result token_native_contract::init_token_api(const std::string& api_name, const std::string& api_arg)
		{
			check_admin();
			if(get_storage_state()!= not_inited_state_of_token_contract)
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "this token contract inited before");
			std::vector<string> parsed_args;
			boost::split(parsed_args, api_arg, boost::is_any_of(","));
			if (parsed_args.size() < 3)
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "argument format error, need format: name,supply,precision");
			string name = parsed_args[0];
			boost::trim(name);
			string supply_str = parsed_args[1];
			if (!is_integral(supply_str))
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "argument format error, need format: name,supply,precision");
			int64_t supply = std::stoll(supply_str);
			if(supply <= 0)
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "argument format error, supply must be positive integer");
			string precision_str = parsed_args[2];
			if(!is_integral(precision_str))
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "argument format error, need format: name,supply,precision");
			int64_t precision = std::stoll(precision_str);
			if(precision <= 0)
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "argument format error, precision must be positive integer");
			// allowedPrecisions = [1,10,100,1000,10000,100000,1000000,10000000,100000000]
			std::vector<int64_t> allowed_precisions = { 1,10,100,1000,10000,100000,1000000,10000000,100000000 };
			if(std::find(allowed_precisions.begin(), allowed_precisions.end(), precision) == allowed_precisions.end())
				FC_THROW_EXCEPTION(blockchain::contract_engine::contract_error, "argument format error, precision must be any one of [1,10,100,1000,10000,100000,1000000,10000000,100000000]");
			set_contract_storage(contract_id, string("state"), string("\"") + "COMMON" + "\"");
			set_contract_storage(contract_id, string("precision"), string("") + std::to_string(precision));
			set_contract_storage(contract_id, string("supply"), string("") + std::to_string(supply));
			set_contract_storage(contract_id, string("name"), string("\"") + name + "\"");

			jsondiff::JsonObject users;
			auto caller_addr = string(*_evaluate.get_caller_address());
			users[caller_addr] = supply;
			set_contract_storage(contract_id, string("users"), jsondiff::json_dumps(users));
			return _contract_invoke_result;
		}

		contract_invoke_result token_native_contract::invoke(const std::string& api_name, const std::string& api_arg) {
			std::map<std::string, std::function<contract_invoke_result(const std::string&, const std::string&)>> apis = {
				{"init", std::bind(&token_native_contract::init_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"init_token", std::bind(&token_native_contract::init_token_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"transfer", std::bind(&token_native_contract::transfer_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"transferFrom", std::bind(&token_native_contract::transfer_from_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"balanceOf", std::bind(&token_native_contract::balance_of_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"approve", std::bind(&token_native_contract::approve_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"approvedBalanceFrom", std::bind(&token_native_contract::approved_balance_from_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"state", std::bind(&token_native_contract::state_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"supply", std::bind(&token_native_contract::supply_api, this, std::placeholders::_1, std::placeholders::_2)},
				{"precision", std::bind(&token_native_contract::precision_api, this, std::placeholders::_1, std::placeholders::_2)}
			};
			if (apis.find(api_name) != apis.end())
				return apis[api_name](api_name, api_arg);
			FC_THROW_EXCEPTION(blockchain::contract_engine::contract_api_not_found, "token api not found");
		}

		bool native_contract_finder::has_native_contract_with_key(const std::string& key)
		{
			std::vector<std::string> native_contract_keys = {
				demo_native_contract::native_contract_key(),
				token_native_contract::native_contract_key()
			};
			return std::find(native_contract_keys.begin(), native_contract_keys.end(), key) != native_contract_keys.end();
		}
		shared_ptr<abstract_native_contract> native_contract_finder::create_native_contract_by_key(common_contract_evaluator evaluate, const std::string& key, const address& contract_address)
		{
			if (key == demo_native_contract::native_contract_key())
			{
				return std::make_shared<demo_native_contract>(evaluate, contract_address);
			}
			else if (key == token_native_contract::native_contract_key())
			{
				return std::make_shared<token_native_contract>(evaluate, contract_address);
			}
			else
			{
				return nullptr;
			}
		}

		void            native_contract_register_operation::validate()const
		{
			FC_ASSERT(init_cost > 0 && init_cost <= BLOCKLINK_MAX_GAS_LIMIT);
			// FC_ASSERT(fee.amount == 0 & fee.asset_id == asset_id_type(0));
			FC_ASSERT(gas_price >= BLOCKLINK_MIN_GAS_PRICE);
			FC_ASSERT(contract_id == calculate_contract_id());
			FC_ASSERT(native_contract_finder::has_native_contract_with_key(native_contract_key));
		}
		share_type      native_contract_register_operation::calculate_fee(const fee_parameters_type& schedule)const
		{
			// base fee
			share_type core_fee_required = schedule.fee;
			core_fee_required += calculate_data_fee(100, schedule.price_per_kbyte); // FIXME: native contract base fee
			return core_fee_required;
		}
		address native_contract_register_operation::calculate_contract_id() const
		{
			address id;
			fc::sha512::encoder enc;
			std::pair<address, fc::time_point> info_to_digest(owner_addr, register_time);
			fc::raw::pack(enc, info_to_digest);
			id.addr = fc::ripemd160::hash(enc.result());
			return id;
		}
	}
}