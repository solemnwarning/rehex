#pragma once

#if defined(SOL_HPP)
#error This header must be included instead of using sol directly!
#endif

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#include "../src/SharedDocumentPointer.hpp"


class IPlugin;

namespace luaenvironment
{
	// Init the (per document) vm
	void initvm(sol::state& lua);
	void exitvm(sol::state& lua);

	// Personalize the (per script) sandbox
	void initenv(sol::environment& env, IPlugin* plugin);
}


namespace sol
{
	template <typename T>
	struct unique_usertype_traits<REHex::SharedDocumentPointerImpl<T>>
	{
		typedef T type;
		typedef REHex::SharedDocumentPointerImpl<T> actual_type;
		static const bool value = true;

		static bool is_null(const actual_type& ptr)
		{
			return ptr == nullptr;
		}

		static type* get(const actual_type& ptr)
		{
			return &*ptr;
		}
	};
}
