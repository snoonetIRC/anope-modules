/* Much of this code was borrowed from os_news.cpp
 */

#include "module.h"

struct ServerNewsItem
	: Serializable
{
	Anope::string text;
	Anope::string who;
	Anope::string server;
	time_t time;

	ServerNewsItem()
		: Serializable("ServerNewsItem")
	{
	}
};

class ServerNewsService
	: public Service
{
 public:
	ServerNewsService(Module* m)
		: Service(m, "ServerNewsService", "server_news")
	{
	}

	virtual ServerNewsItem* CreateNewsItem() = 0;

	virtual void AddNewsItem(ServerNewsItem* n) = 0;

	virtual void DelNewsItem(ServerNewsItem* n) = 0;

	virtual std::vector<ServerNewsItem*>& GetNewsList() = 0;
};

static ServiceReference<ServerNewsService> news_service("ServerNewsService", "server_news");

struct MyNewsItem
	: ServerNewsItem
{
	void Serialize(Serialize::Data& data) const anope_override
	{
		data["text"] << this->text;
		data["who"] << this->who;
		data["time"] << this->time;
		data["server"] << this->server;
	}

	static Serializable* Unserialize(Serializable* obj, Serialize::Data& data)
	{
		if (!news_service)
			return NULL;

		ServerNewsItem* ni;
		if (obj)
			ni = anope_dynamic_static_cast<ServerNewsItem*>(obj);
		else
			ni = news_service->CreateNewsItem();

		data["text"] >> ni->text;
		data["who"] >> ni->who;
		data["time"] >> ni->time;
		data["server"] >> ni->server;

		if (!obj)
			news_service->AddNewsItem(ni);
		return ni;
	}
};

typedef std::vector<ServerNewsItem*> NewsItems;

class MyNewsService
	: public ServerNewsService
{
	NewsItems newsItems;
 public:
	MyNewsService(Module* m)
		: ServerNewsService(m)
	{
	}

	~MyNewsService()
	{
		for (unsigned j = 0; j < newsItems.size(); ++j)
			delete newsItems[j];
	}

	ServerNewsItem* CreateNewsItem() anope_override
	{
		return new MyNewsItem();
	}

	void AddNewsItem(ServerNewsItem* n)
	{
		this->newsItems.push_back(n);
		n->QueueUpdate();
	}

	void DelNewsItem(ServerNewsItem* n)
	{
		NewsItems& list = this->GetNewsList();
		NewsItems::iterator it = std::find(list.begin(), list.end(), n);
		if (it != list.end())
			list.erase(it);
		delete n;
	}

	NewsItems& GetNewsList()
	{
		return this->newsItems;
	}

	NewsItems GetNewsItemsForServer(Server* s)
	{
		NewsItems out;
		NewsItems news = GetNewsList();
		for (NewsItems::size_type i = 0; i < news.size(); ++i)
		{
			NewsItems::reference item = news[i];
			if (Anope::Match(s->GetName(), item->server, false, true))
				out.push_back(item);
		}
		return out;
	}
};

class CommandOSServerNews
	: public Command
{
	ServiceReference<ServerNewsService> ns;

 protected:
	void DoList(CommandSource& source)
	{
		NewsItems& list = this->ns->GetNewsList();
		if (list.empty())
			source.Reply(_("There is no server news."));
		else
		{
			ListFormatter lflist(source.GetAccount());
			lflist.AddColumn(_("Number")).AddColumn(_("Creator")).AddColumn(_("Created")).AddColumn(
				_("Server")).AddColumn(_("Text"));

			for (unsigned i = 0, end = list.size(); i < end; ++i)
			{
				ListFormatter::ListEntry entry;
				entry["Number"] = stringify(i + 1);
				entry["Creator"] = list[i]->who;
				entry["Created"] = Anope::strftime(list[i]->time, NULL, true);
				entry["Server"] = list[i]->server;
				entry["Text"] = list[i]->text;
				lflist.AddEntry(entry);
			}

			source.Reply(_("Server news items:"));

			std::vector<Anope::string> replies;
			lflist.Process(replies);

			for (unsigned i = 0; i < replies.size(); ++i)
				source.Reply(replies[i]);

			source.Reply(_("End of news list."));
		}
	}

	void DoAdd(CommandSource& source, const std::vector<Anope::string>& params)
	{
		Anope::string text, server;
		server = params.size() > 1 ? params[1] : "";
		text = params.size() > 2 ? params[2] : "";

		if (text.empty() || server.empty())
			this->OnSyntaxError(source, "ADD");
		else
		{
			if (Anope::ReadOnly)
				source.Reply(READ_ONLY_MODE);

			ServerNewsItem* news = this->ns->CreateNewsItem();
			news->text = text;
			news->time = Anope::CurTime;
			news->who = source.GetNick();
			news->server = server;

			this->ns->AddNewsItem(news);

			source.Reply(_("Added new server news item."));
			Log(LOG_ADMIN, source, this) << "to add a news item";
		}
	}

	void DoDel(CommandSource& source, const std::vector<Anope::string>& params)
	{
		const Anope::string& text = params.size() > 1 ? params[1] : "";

		if (text.empty())
			this->OnSyntaxError(source, "DEL");
		else
		{
			NewsItems& list = this->ns->GetNewsList();
			if (list.empty())
				source.Reply(_("There is no server news."));
			else
			{
				if (Anope::ReadOnly)
					source.Reply(READ_ONLY_MODE);
				if (!text.equals_ci("ALL"))
				{
					try
					{
						unsigned num = convertTo<unsigned>(text);
						if (num > 0 && num <= list.size())
						{
							this->ns->DelNewsItem(list[num - 1]);
							source.Reply(_("Server news item #%d deleted."), num);
							Log(LOG_ADMIN, source, this) << "to delete a news item";
							return;
						}
					}
					catch (const ConvertException&)
					{
					}

					source.Reply(_("Server news item #%s not found!"), text.c_str());
				}
				else
				{
					for (unsigned i = list.size(); i > 0; --i)
						this->ns->DelNewsItem(list[i - 1]);
					source.Reply(_("All server news items deleted."));
					Log(LOG_ADMIN, source, this) << "to delete all news items";
				}
			}
		}
	}

	void DoNews(CommandSource& source, const std::vector<Anope::string>& params)
	{
		if (!this->ns)
			return;

		const Anope::string& cmd = params[0];

		if (cmd.equals_ci("LIST"))
			return this->DoList(source);
		else if (cmd.equals_ci("ADD"))
			return this->DoAdd(source, params);
		else if (cmd.equals_ci("DEL"))
			return this->DoDel(source, params);
		else
			this->OnSyntaxError(source, "");
	}

 public:
	CommandOSServerNews(Module* creator)
		: Command(creator, "operserv/servernews", 1, 3)
		, ns(news_service)
	{
		this->SetDesc(_("Define messages to be shown to users on specific servers at logon"));

		this->SetSyntax(_("ADD \037server\037 \037text\037"));
		this->SetSyntax(_("DEL {\037num\037 | ALL}"));
		this->SetSyntax("LIST");
	}

	void Execute(CommandSource& source, const std::vector<Anope::string>& params) anope_override
	{
		return this->DoNews(source, params);
	}

	bool OnHelp(CommandSource& source, const Anope::string& subcommand) anope_override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Edits or displays the list of server specific logon news messages.\n"
					   "When a user connects to the network, these messages will be sent\n"
					   "to them if they are on the specific server."));
		return true;
	}
};

class OSNews
	: public Module
{
	MyNewsService newsservice;
	Serialize::Type newsitem_type;

	CommandOSServerNews commandOSServerNews;

	Anope::string announcer;

	void DisplayNews(User* u)
	{
		NewsItems newsList = this->newsservice.GetNewsItemsForServer(u->server);
		if (newsList.empty())
			return;

		BotInfo* bi = BotInfo::Find(announcer, true);
		if (bi == NULL)
			return;

		Anope::string msg = _("[\002Logon News\002 - %s] %s");

		for (unsigned i = 0, end = newsList.size(); i < end; ++i)
		{
			u->SendMessage(bi, msg.c_str(), Anope::strftime(newsList[i]->time, u->Account(), true).c_str(),
						   newsList[i]->text.c_str());
		}
	}

 public:
	OSNews(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, newsservice(this)
		, newsitem_type("ServerNewsItem", MyNewsItem::Unserialize)
		, commandOSServerNews(this)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.1");
	}

	void OnReload(Configuration::Conf* conf) anope_override
	{
		announcer = conf->GetModule(this)->Get<const Anope::string>("announcer", "Global");
	}

	void OnUserConnect(User* user, bool&) anope_override
	{
		if (user->Quitting() || !user->server->IsSynced())
			return;

		DisplayNews(user);
	}
};

MODULE_INIT(OSNews)
