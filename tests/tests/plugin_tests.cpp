#include <boost/test/unit_test.hpp>
#include <fc/variant_object.hpp>
#include <iostream>
#include <graphene/crosschain/crosschain.hpp>
#include <graphene/crosschain/crosschain_impl.hpp>
#include <boost/filesystem.hpp>
/*
need a normal account
need a multisig account

*/

static struct
{
	//graphene::crosschain::crosschain_manager manager;
	//_wallet;
	std::string normal_address;
	std::string multi_sig_address;
	
} plugin_data;
static void setup_env()
{
	
}
#define INVOKE(test) ((struct test*)this)->test_method(); 

BOOST_AUTO_TEST_SUITE(plugin_test)

BOOST_AUTO_TEST_CASE(plugin_wallet_create_operation)
{
	//create wallet
	auto& manager = graphene::crosschain::crosschain_manager::get_instance();
	auto hdl = manager.get_crosschain_handle(std::string("EMU"));
	if(!hdl->create_wallet("test", "12345678"))
	hdl->open_wallet("test");
	hdl->unlock_wallet("test","12345678",100000);
	

	std::string temp_path = boost::filesystem::initial_path<boost::filesystem::path>().string();
	temp_path += "/";
	boost::filesystem::remove(temp_path + "test");
	//open unlock lock close wallet

	//auto _wallet = create_wallet();
}

BOOST_AUTO_TEST_CASE(plugin_account_operation)
{
	//create normal account
	auto& manager = graphene::crosschain::crosschain_manager::get_instance();
	auto hdl = manager.get_crosschain_handle(std::string("EMU"));
	if (!hdl->create_wallet("test", "12345678"))
		hdl->open_wallet("test");
	hdl->unlock_wallet("test", "12345678", 100000);
	hdl->create_normal_account("test_account");
	std::string temp_path = boost::filesystem::initial_path<boost::filesystem::path>().string();
	temp_path += "/";
	boost::filesystem::remove(temp_path + "test");
	
}

BOOST_AUTO_TEST_CASE(plugin_transfer)
{
	auto& manager = graphene::crosschain::crosschain_manager::get_instance();
	auto hdl = manager.get_crosschain_handle(std::string("EMU"));
	//transfer normal trx
	auto trx = hdl->transfer(std::string("test_account"), std::string("to_account"), 1, std::string("mBTC"), std::string(""), true);
	hdl->broadcast_transaction(trx);
	//check balance of account
	auto ret = hdl->query_account_balance(std::string("to_account"));
	for (auto var : ret)
	{
		auto iter = var.find("to_account");
		BOOST_CHECK_EQUAL(iter!=var.end(),true);
		BOOST_CHECK_EQUAL(iter->value().as_uint64(),1);
		
	}
}


BOOST_AUTO_TEST_CASE(plugin_create_multi_account)
{
	//create multi_account
	auto& manager = graphene::crosschain::crosschain_manager::get_instance();
	auto hdl = manager.get_crosschain_handle(std::string("EMU"));
	std::vector<std::string> vec{"str1","str2"};

	if (!hdl->create_wallet("test", "12345678"))
		hdl->open_wallet("test");
	hdl->unlock_wallet("test", "12345678", 100000);
    auto addr = hdl->create_multi_sig_account("multi_sig_account",vec,2); //n/m 
	plugin_data.multi_sig_address = addr;
	std::string temp_path = boost::filesystem::initial_path<boost::filesystem::path>().string();
	temp_path += "/";
	boost::filesystem::remove(temp_path + "test");

}

BOOST_AUTO_TEST_CASE(plugin_transfer_multi)
{
	auto& manager = graphene::crosschain::crosschain_manager::get_instance();
	auto hdl = manager.get_crosschain_handle(std::string("EMU"));

	auto trx = hdl->create_multisig_transaction(std::string("multi_sig_account"),std::string("toaccount"),"10",std::string("mBTC"),std::string(""),true);
	//sign
	auto signature = hdl->sign_multisig_transaction(trx,std::string("sign_account"),true);
	
	std::vector<std::string> vec;
	vec.push_back(signature);
	//merge
	hdl->merge_multisig_transaction(trx,vec);
	hdl->broadcast_transaction(trx);

}

BOOST_AUTO_TEST_CASE(plugin_transfer_history)
{
	//get history of transactions
	INVOKE(plugin_transfer)
	auto& manager = graphene::crosschain::crosschain_manager::get_instance();
	auto hdl = manager.get_crosschain_handle(std::string("EMU"));
    auto ret = hdl->transaction_history(std::string("test_account"), 0, 10);
	BOOST_CHECK_EQUAL(ret.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
