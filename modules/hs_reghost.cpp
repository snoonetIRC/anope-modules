/*
 * Config:
 * 		module
 * 		{
 * 			name = "hs_reghost"
 * 			prefix = "user/"
 * 			suffix = ""
 * 			hashPrefix = "/x-"
 * 			replaceChar = "-"
 * 			server
 * 			{
 * 				pattern = "*.example.com"
 * 				prefix = "example.com/"
 * 			}
 * 			server
 * 			{
 * 				pattern = "*.example.net"
 * 				prefix = "example.net/"
 * 				default = true
 * 			}
 * 		}
 * */

#include "module.h"

struct ServerVHost
{
	Anope::string serverPattern;
	Anope::string prefix;

	ServerVHost(const Anope::string& pattern, const Anope::string& pfx)
		: serverPattern(pattern)
		, prefix(pfx)
	{
	}

	bool MatchServer(Server* server) const
	{
		return Anope::Match(server->GetName(), serverPattern, false, true);
	}
};

typedef std::vector<ServerVHost*> VhostList;

class HSRegHost
	: public Module
{
 private:
	bool synconset;
	bool requireConfirm;
	char replaceChar;
	Anope::string prefix;
	Anope::string suffix;
	Anope::string hashPrefix;
	std::set<char> validChars;
	std::set<char> invalidStartEndChars;
	Reference<BotInfo> HostServ;
	VhostList vhosts;

	void Sync(const NickAlias* na)
	{
		if (!na || !na->HasVhost())
			return;

		for (unsigned i = 0; i < na->nc->aliases->size(); ++i)
		{
			NickAlias* nick = na->nc->aliases->at(i);
			if (nick)
				nick->SetVhost(na->GetVhostIdent(), na->GetVhostHost(), na->GetVhostCreator());
		}
	}

	Anope::string GetDescriminator(NickAlias* na)
	{
		std::stringstream sstr;
		sstr << std::hex << na->time_registered;
		return sstr.str();
	}

	ServerVHost* GetServerPrefix(Server* server)
	{
		if (vhosts.empty())
			return NULL;

		if (!server)
			return vhosts.front();

		for (VhostList::const_iterator it = vhosts.begin(), it_end = vhosts.end(); it != it_end; ++it)
		{
			if ((*it)->MatchServer(server))
				return *it;
		}
		return vhosts.front();
	}

	Anope::string GenVhost(const Anope::string& hostPrefix, NickAlias* user,
						   const Anope::string& hostSuffix, Server* server)
	{
		ServerVHost* serverVHost = GetServerPrefix(server);
		Anope::string serverPrefix = serverVHost ? serverVHost->prefix : "";

		Anope::string vhost = serverPrefix + hostPrefix + user->nick + hostSuffix;
		bool valid = true;
		for (Anope::string::iterator i = vhost.begin(); i != vhost.end(); ++i)
		{
			if (validChars.find(*i) == validChars.end())
			{
				*i = replaceChar;
				valid = false;
			}
		}

		// Check first character of the vhost
		if (invalidStartEndChars.find(vhost[0]) != invalidStartEndChars.end())
		{
			vhost[0] = replaceChar;
			valid = false;
		}

		// Check last character of the vhost
		if (invalidStartEndChars.find(vhost[vhost.length() - 1]) != invalidStartEndChars.end())
		{
			vhost[vhost.length() - 1] = replaceChar;
			valid = false;
		}

		if (!valid)
			vhost += hashPrefix + GetDescriminator(user);

		return vhost;
	}

	void SetVHost(NickAlias* na)
	{
		Anope::string setter = HostServ->nick;
		User* u = User::Find(na->nick);
		Anope::string vhost = GenVhost(prefix, na, suffix, u ? u->server : NULL);

		if (!IRCD->IsHostValid(vhost))
			return;

		na->SetVhost(na->GetVhostIdent(), vhost, setter);

		// If the network has module::hs_group::synconset = true then we have to manually set the vhost
		// to avoid sending duplicate "Your vhost is activated" messages
		if (!synconset)
		{
			FOREACH_MOD(OnSetVhost, (na));
		}
		else
		{
			// Mimic the HostServ core functionality

			if (u && u->Account() == na->nc)
			{
				IRCD->SendVhost(u, na->GetVhostIdent(), na->GetVhostHost());

				u->vhost = na->GetVhostHost();
				u->UpdateHost();

				if (IRCD->CanSetVIdent && !na->GetVhostIdent().empty())
					u->SetVIdent(na->GetVhostIdent());

				if (HostServ)
				{
					if (!na->GetVhostIdent().empty())
						u->SendMessage(HostServ, _("Your vhost of \002%s\002@\002%s\002 is now activated."),
									   na->GetVhostIdent().c_str(), na->GetVhostHost().c_str());
					else
						u->SendMessage(HostServ, _("Your vhost of \002%s\002 is now activated."),
									   na->GetVhostHost().c_str());
				}
			}
		}
		// Set the vhost across all the user's NickAliases
		this->Sync(na);
	}

	void ClearConfig()
	{
		for (VhostList::const_iterator it = vhosts.begin(), it_end = vhosts.end(); it != it_end; ++it)
			delete *it;

		vhosts.clear();
	}

 public:
	HSRegHost(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, synconset(false)
		, requireConfirm(false)
		, replaceChar('-')
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.4");
	}

	~HSRegHost()
	{
		ClearConfig();
	}

	void Prioritize() anope_override
	{
		ModuleManager::SetPriority(this, PRIORITY_LAST);
	}

	void OnNickRegister(User* user, NickAlias* na, const Anope::string& pass) anope_override
	{
		if (!requireConfirm)
			SetVHost(na);
	}

	void OnNickConfirm(User* user, NickCore* nc) anope_override
	{
		SetVHost(nc->aliases->at(0));
	}

	void OnChangeCoreDisplay(NickCore* nc, const Anope::string& newdisplay) anope_override
	{
		for (std::vector<NickAlias*>::const_iterator it = nc->aliases->begin(); it != nc->aliases->end(); it++)
		{
			if ((*it)->nick == newdisplay)
			{
				SetVHost((*it));
				break;
			}
		}
	}

	void OnReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* block = conf->GetModule(this);
		Configuration::Block* hostServ = conf->GetModule("hostserv");
		Configuration::Block* hsGroup = conf->GetModule("hs_group");
		Configuration::Block* nsRegister = conf->GetModule("ns_register");
		Configuration::Block* netInfo = conf->GetBlock("networkinfo");

		if (!block)
			throw ConfigException(this->name + ": Config block appears undefined?! This is almost certainly a bug");

		prefix = block->Get<const Anope::string>("prefix");
		suffix = block->Get<const Anope::string>("suffix");
		hashPrefix = block->Get<const Anope::string>("hashPrefix");
		Anope::string replaceChars = block->Get<const Anope::string>("replaceChar", "-");

		if (replaceChars.length() != 1)
		{
			Log(this) << this->name + ":replaceChar must be a single character, using default";
			replaceChar = '-';
		}
		else
		{
			replaceChar = replaceChars[0];
		}

		ClearConfig();
		for (int i = 0; i < block->CountBlock("server"); ++i)
		{
			Configuration::Block* serverBlock = block->GetBlock("server", i);
			ServerVHost* vhost = new ServerVHost(serverBlock->Get<const Anope::string>("pattern"),
												 serverBlock->Get<const Anope::string>("prefix"));
			if (serverBlock->Get<bool>("default"))
				vhosts.insert(vhosts.begin(), vhost);
			else
				vhosts.push_back(vhost);
		}

		if (nsRegister)
			requireConfirm = nsRegister->Get<const Anope::string>("registration") != "none";
		else
			Log(this) << "ns_register does not appear to be loaded. This module is useless without it";

		synconset = hsGroup && hsGroup->Get<bool>("synconset");

		if (!hostServ)
			throw ConfigException(this->name + ": This module requires HostServ to function");

		Anope::string hsnick = hostServ->Get<const Anope::string>("client");
		if (hsnick.empty())
			throw ConfigException(this->name + ": <hostserv:client> must be defined");

		BotInfo* bi = BotInfo::Find(hsnick, true);
		if (!bi)
			throw ConfigException(this->name + ": no bot named " + hsnick);

		HostServ = bi;

		if (!netInfo)
			throw ConfigException(this->name + ": networkinfo block appears undefined, this is a bug!");

		Anope::string badStartChars = netInfo->Get<const Anope::string>("disallow_start_or_end");
		Anope::string vhostChars = netInfo->Get<const Anope::string>("vhost_chars");
		validChars = std::set<char>(vhostChars.begin(), vhostChars.end());
		invalidStartEndChars = std::set<char>(badStartChars.begin(), badStartChars.end());
	}
};

MODULE_INIT(HSRegHost)
