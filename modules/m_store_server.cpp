#include "module.h"

class ModuleStoreServer
	: public Module
{
	SerializableExtensibleItem<Anope::string> serverExt;
 public:
	ModuleStoreServer(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, serverExt(this, "REGSERVER")
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.1");
	}

	virtual void OnNickRegister(User* user, NickAlias* na, const Anope::string& pass)
	{
		if (!na || !na->nc)
			return;

		serverExt.Set(na->nc, user ? user->server->GetName() : "");
		na->QueueUpdate();
		na->nc->QueueUpdate();
	}

	virtual void OnPostCommand(CommandSource& source, Command* command, const std::vector<Anope::string>& params)
	{
		NickCore* nc = source.GetAccount();
		if (!nc || serverExt.HasExt(nc))
			return;

		User* u = source.GetUser();
		if (!u || !u->server)
			return;

		serverExt.Set(nc, u->server->GetName());
		nc->QueueUpdate();
	}
};

MODULE_INIT(ModuleStoreServer)
