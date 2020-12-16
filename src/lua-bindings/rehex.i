#include "../app.hpp"

// TODO: Make this a proper enum class?
enum REHex::App::SetupPhase
{};

#define App_SetupPhase_EARLY (double)(REHex::App::SetupPhase::EARLY)
#define App_SetupPhase_READY (double)(REHex::App::SetupPhase::READY)
#define App_SetupPhase_DONE  (double)(REHex::App::SetupPhase::DONE)

// TODO: Less obnoxious name in Lua environment.
class %delete REHex::App::SetupHookRegistration
{
	REHex::App::SetupHookRegistration(REHex::App::SetupPhase phase, const LuaFunction func);
};
