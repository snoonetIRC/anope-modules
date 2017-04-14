#include "module.h"

class HSRegHost : public Module
{
 private:
	Anope::string prefix;
	Anope::string suffix;
	Anope::string hashPrefix;
	bool synconset;
	Reference<BotInfo> HostServ;

	Anope::string HashNick(const Anope::string &nick)
	{
		// TODO implement an actual hash
		Anope::string hash;
		for (int i = 0; i < 8; ++i)
			hash += '0' + (std::rand() % 10);

		return hash;
	}

	Anope::string CleanNick(Anope::string &nick)
	{
		Anope::string oldNick = nick;
		Configuration::Block *niblock = Config->GetBlock("networkinfo");
		const Anope::string &badStartChars = niblock->Get<const Anope::string>("disallow_start_or_end");
		const Anope::string &vhostChars = niblock->Get<const Anope::string>("vhost_chars");
		bool nickValid = true;

		// Only check the first character of the nick if the VHost prefix is empty
		if (prefix.empty() && badStartChars.find_first_of(nick[0]) != std::string::npos)
		{
			nick[0] = '-';
			nickValid = false;
		}

		if (badStartChars.find_first_of(nick[nick.length() - 1]) != std::string::npos)
		{
			nick[nick.length() - 1] = '-';
			nickValid = false;
		}

		for (Anope::string::size_type i = 0; i < nick.length(); ++i)
		{
			if (vhostChars.find_first_of(nick[i]) == std::string::npos)
			{
				nick[i] = '-';
				nickValid = false;
			}
		}

		return !nickValid ? HashNick(oldNick) : "";
	}

	void SetVHost(NickAlias *na)
	{
		Anope::string nick = na->nick;
		Anope::string setter = "HostServ";
		Anope::string ident; // Vidents aren't handled
		Anope::string nickHash = CleanNick(nick);
		Anope::string vhost = prefix + nick + suffix + (!nickHash.empty() ? hashPrefix + nickHash : "");

		if (!IRCD->IsHostValid(vhost))
			return;

		na->SetVhost(ident, vhost, setter);

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
	}

 public:
	HSRegHost(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, THIRD)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.2");
	}

	void Prioritize() anope_override
	{
		ModuleManager::SetPriority(this, PRIORITY_LAST);
	}

	void OnNickRegister(User *user, NickAlias *na, const Anope::string &pass) anope_override
	{
		if (Config->GetModule("ns_register")->Get<const Anope::string>("registration") == "none")
			SetVHost(na);
	}

	void OnNickConfirm(User *user, NickCore *nc) anope_override
	{
		SetVHost(nc->aliases->at(0));
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		Configuration::Block *block = conf->GetModule(this);
		prefix = block->Get<Anope::string>("prefix", "");
		suffix = block->Get<Anope::string>("suffix", "");
		hashPrefix = block->Get<Anope::string>("hashPrefix", "");
		synconset = false;

		Configuration::Block *hsconf = conf->GetModule("hs_group");
		if (hsconf)
			synconset = hsconf->Get<bool>("synconset");

		const Anope::string &hsnick = conf->GetModule("hostserv")->Get<const Anope::string>("client");
		if (hsnick.empty())
			throw ConfigException("hs_reghost: <client> must be defined");

		BotInfo *bi = BotInfo::Find(hsnick, true);
		if (!bi)
			throw ConfigException("hs_reghost: no bot named " + hsnick);

		HostServ = bi;
	}
};

MODULE_INIT(HSRegHost)

