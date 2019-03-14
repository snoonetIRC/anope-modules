/**
 * Removes the PERM channel mode when a channel is unregistered
 * */

#include "module.h"


class ModuleUnsetPersist
	: public Module
{
 public:
	ModuleUnsetPersist(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.1");
	}

	void OnDelChan(ChannelInfo* ci) anope_override
	{
		if (ci->c)
		{
			ci->c->RemoveMode(ci->WhoSends(), "PERM", "", false);
		}
	}
};

MODULE_INIT(ModuleUnsetPersist)
