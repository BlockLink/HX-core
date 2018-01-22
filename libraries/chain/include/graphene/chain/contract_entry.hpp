#pragma once

#include <graphene/chain/protocol/base.hpp>
#include <graphene/chain/protocol/memo.hpp>
#include <graphene/db/generic_index.hpp>
#include <boost/multi_index/composite_key.hpp>

#include <uvm/uvm_lib.h>
#include <fc/exception/exception.hpp>
//#include <graphene/chain/protocol/operations.hpp>


namespace blockchain
{
	namespace contract_engine
	{

		FC_DECLARE_EXCEPTION(uvm_exception, 34000, "uvm error");
		FC_DECLARE_DERIVED_EXCEPTION(contract_run_out_of_money, blockchain::contract_engine::uvm_exception, 34004, "contract run out of money error");
		FC_DECLARE_DERIVED_EXCEPTION(uvm_executor_internal_error, blockchain::contract_engine::uvm_exception, 34005, "uvm internal error");
		FC_DECLARE_DERIVED_EXCEPTION(read_verify_code_fail, blockchain::contract_engine::uvm_exception, 34006, "read verify contract bytecode error");
		FC_DECLARE_DERIVED_EXCEPTION(read_bytescode_len_fail, blockchain::contract_engine::uvm_exception, 34007, "read contract bytecode length error");
		FC_DECLARE_DERIVED_EXCEPTION(read_bytescode_fail, blockchain::contract_engine::uvm_exception, 34008, "read cotnract bytecode error");
		FC_DECLARE_DERIVED_EXCEPTION(verify_bytescode_sha1_fail, blockchain::contract_engine::uvm_exception, 34009, "verify bytecode sha1 error");
		FC_DECLARE_DERIVED_EXCEPTION(read_api_count_fail, blockchain::contract_engine::uvm_exception, 34010, "read api count fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_api_len_fail, blockchain::contract_engine::uvm_exception, 34011, "read api len fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_offline_api_count_fail, blockchain::contract_engine::uvm_exception, 34012, "read offline api count_fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_offline_api_len_fail, blockchain::contract_engine::uvm_exception, 34013, "read offline api len fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_events_count_fail, blockchain::contract_engine::uvm_exception, 34014, "read events count fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_events_len_fail, blockchain::contract_engine::uvm_exception, 34015, "read events len fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_storage_count_fail, blockchain::contract_engine::uvm_exception, 34016, "read storage count fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_storage_name_len_fail, blockchain::contract_engine::uvm_exception, 34017, "read storage name len fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_api_fail, blockchain::contract_engine::uvm_exception, 34018, "read api fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_offline_api_fail, blockchain::contract_engine::uvm_exception, 34019, "read offline api fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_events_fail, blockchain::contract_engine::uvm_exception, 34020, "read events fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_storage_name_fail, blockchain::contract_engine::uvm_exception, 34021, "read storage name fail");
		FC_DECLARE_DERIVED_EXCEPTION(read_storage_type_fail, blockchain::contract_engine::uvm_exception, 34022, "read storage type fail");

		FC_DECLARE_EXCEPTION(contract_error, 35000, "contract error");
	}
}

#include <graphene/db/generic_index.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <graphene/chain/storage.hpp>
namespace uvm {
	namespace blockchain {
		struct Code
		{
			std::set<std::string> abi;
			std::set<std::string> offline_abi;
			std::set<std::string> events;
			std::map<std::string, fc::enum_type<fc::unsigned_int, uvm::blockchain::StorageValueTypes>> storage_properties;
			std::vector<unsigned char> code;
			std::string code_hash;
			Code() {}
			void SetApis(char* module_apis[], int count, int api_type);
			bool valid() const;
			std::string GetHash() const;
		};
	}
}

namespace graphene {
	namespace chain {

		enum ContractApiType
		{
			chain = 1,
			offline = 2,
			event = 3
		};

		

		struct CodePrintAble
		{
			std::set<std::string> abi;
			std::set<std::string> offline_abi;
			std::set<std::string> events;
			std::map<std::string, std::string> printable_storage_properties;
			std::string printable_code;
			std::string code_hash;

			CodePrintAble() {}

			CodePrintAble(const uvm::blockchain::Code& code);
		};

		struct ContractEntryPrintable
		{
			std::string  id; //contract address
			public_key_type owner; //the owner of the contract
			address owner_address;  //the owner address of the contract
			string owner_name;  //the owner name of the contract
			CodePrintAble code_printable; // code-related of contract
            fc::time_point_sec createtime;
		};

		typedef uint64_t gas_price_type;
		typedef uint64_t gas_count_type;
        
	}
}

FC_REFLECT(uvm::blockchain::Code, (abi)(offline_abi)(events)(storage_properties)(code)(code_hash));

FC_REFLECT(graphene::chain::CodePrintAble, (abi)(offline_abi)(events)(printable_storage_properties)(printable_code)(code_hash));
FC_REFLECT(graphene::chain::ContractEntryPrintable, (id)(owner)(owner_address)(owner_name)(code_printable)(createtime));

