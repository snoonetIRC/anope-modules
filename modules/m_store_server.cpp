#include "module.h"

class ModuleStoreServer
	: public Module
{
	void SetServer(const Serialize::Reference<NickCore>& nc, User* user)
	{
		if (!nc)
			return;

		Anope::string* ext = serverExt.Get(nc);
		if (ext && !ext->empty())
			return;

		serverExt.Set(nc, user && user->server ? user->server->GetName() : "");
	}

	SerializableExtensibleItem<Anope::string> serverExt;

 public:
	ModuleStoreServer(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, serverExt(this, "REGSERVER")
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.2");
	}

	void OnNickRegister(User* user, NickAlias* na, const Anope::string&) anope_override
	{
		if (!na)
			return;

		SetServer(na->nc, user);
	}

	void OnPostCommand(CommandSource& source, Command*, const std::vector<Anope::string>&)  anope_override
	{
		SetServer(source.GetAccount(), source.GetUser());
	}
};

MODULE_INIT(ModuleStoreServer)
