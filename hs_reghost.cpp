/*
 * Config:
 * 		module
 * 		{
 * 			name = "hs_reghost"
 * 			prefix = "user/"
 * 			suffix = ""
 * 			hashPrefix = "/x-"
 * 			replaceChar = "-"
 * 		}
 * */

#include "module.h"

class HSRegHost : public Module
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

	void Sync(const NickAlias *na)
	{
		if (!na || !na->HasVhost())
			return;

		for (unsigned i = 0; i < na->nc->aliases->size(); ++i)
		{
			NickAlias *nick = na->nc->aliases->at(i);
			if (nick)
				nick->SetVhost(na->GetVhostIdent(), na->GetVhostHost(), na->GetVhostCreator());
		}
	}

	Anope::string GetDescriminator(NickAlias *na)
	{
		std::stringstream sstr;
		sstr << std::hex << na->time_registered;
		return sstr.str();
	}

	Anope::string GenVhost(const Anope::string &hostPrefix, NickAlias *user, const Anope::string &hostSuffix)
	{
		Anope::string vhost = hostPrefix + user->nick + hostSuffix;
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

	void SetVHost(NickAlias *na)
	{
		Anope::string setter = HostServ->nick;
		Anope::string vhost = GenVhost(prefix, na, suffix);

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
			User *u = User::Find(na->nick);

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

 public:
	HSRegHost(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, THIRD)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.3");
	}

	void Prioritize() anope_override
	{
		ModuleManager::SetPriority(this, PRIORITY_LAST);
	}

	void OnNickRegister(User *user, NickAlias *na, const Anope::string &pass) anope_override
	{
		if (!requireConfirm)
			SetVHost(na);
	}

	void OnNickConfirm(User *user, NickCore *nc) anope_override
	{
		SetVHost(nc->aliases->at(0));
	}

	void OnChangeCoreDisplay(NickCore *nc, const Anope::string &newdisplay) anope_override
	{
		for (std::vector<NickAlias *>::const_iterator it = nc->aliases->begin(); it != nc->aliases->end(); it++)
		{
			if ((*it)->nick == newdisplay)
			{
				SetVHost((*it));
				break;
			}
		}
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		Configuration::Block *block = conf->GetModule(this);
		Configuration::Block *hostServ = conf->GetModule("hostserv");
		Configuration::Block *hsGroup = conf->GetModule("hs_group");
		Configuration::Block *nsRegister = conf->GetModule("ns_register");
		Configuration::Block *netInfo = conf->GetBlock("networkinfo");

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

		BotInfo *bi = BotInfo::Find(hsnick, true);
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
