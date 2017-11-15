#include <mutex>
#include "graphene/crosschain/crosschain.hpp"
#include "graphene/crosschain/crosschain_impl.hpp"
#include "graphene/crosschain/crosschain_interface_emu.hpp"
#include <graphene/crosschain/crosschain_interface_btc.hpp>
namespace graphene {
	namespace crosschain {
		crosschain_manager::crosschain_manager()
		{
		}

		crosschain_manager::~crosschain_manager()
		{
		}
		
		abstract_crosschain_interface * crosschain_manager::get_crosschain_handle(const std::string &name)
		{
			//std::lock_guard<std::mutex> lgd(mutex);
			auto &itr = crosschain_handles.find(name);
			if (itr != crosschain_handles.end())
			{
				return itr->second;
			}
			else
			{
				if (name == "EMU")
				{
					auto &itr = crosschain_handles.insert(std::make_pair(name, new crosschain_interface_emu()));
					return itr.first->second;
				}
				else if (name == "BTC")
				{
					auto &itr = crosschain_handles.insert(std::make_pair(name, new crosschain_interface_btc()));
					return itr.first->second;
				}
			}
		}
	}
}

void stub(void)
{
	return;
}