#include "module.h"
#include "modules/sql.h"

class MySQLInterface : public SQL::Interface
{
 public:
	unsigned int nicklen;
	Anope::string prefix;
	ServiceReference<SQL::Provider> provider;

	MySQLInterface(Module *module)
		: SQL::Interface(module)
	{
	}

	void CreateTable()
	{
		if (!provider)
			return;

		SQL::Query query = "CREATE TABLE IF NOT EXISTS `" + prefix + "eventlog` ("
			"  `id`           INT                PRIMARY KEY AUTO_INCREMENT,"
			"  `time`         TIMESTAMP          NOT NULL,"
			"  `event`        VARCHAR(25)        NOT NULL,"
			"  `account_id`   BIGINT UNSIGNED    NOT NULL,"
			"  `account_name` VARCHAR(" + stringify(nicklen) + ") NOT NULL,"
			"  `extra_data`   TEXT,"
			"INDEX (`time`)"
			");";
		provider->Run(this, query);
	}

	void InsertRow(const Anope::string &event, uint64_t accid, const Anope::string &accname)
	{
		if (!provider)
			return;

		SQL::Query query = "INSERT INTO `" + prefix + "eventlog`(`time`, `event`, `account_id`, `account_name`)"
			" VALUES (@time@, @event@, @account_id@, @account_name@);";

		query.SetValue("time", provider->FromUnixtime(Anope::CurTime), false);
		query.SetValue("event", event);
		query.SetValue("account_id", accid);
		query.SetValue("account_name", accname);
		provider->Run(this, query);
	}

	void OnResult(const SQL::Result &result) anope_override
	{
		// Nothing interesting happens here.
	}

	void OnError(const SQL::Result &result) anope_override
	{
		Log(owner) << "SQL error: " << result.GetError();
	}

};

class ModuleEventLog
	: public Module
{
private:
	MySQLInterface sqli;

public:
	ModuleEventLog(const Anope::string &modname, const Anope::string &creator)
		: Module(modname, creator, THIRD)
		, sqli(this)
	{
	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		sqli.nicklen = Config->GetBlock("networkinfo")->Get<unsigned>("nicklen");

		Configuration::Block *block = conf->GetModule(this);
		sqli.prefix = block->Get<const Anope::string>("prefix", "anope_");

		const Anope::string engine = block->Get<const Anope::string>("engine", "mysql/main");
		sqli.provider = ServiceReference<SQL::Provider>("SQL::Provider", engine);
		if (sqli.provider)
			sqli.CreateTable();
		else
			Log(this) << "no database connection to " << engine;
	}


	void OnNickRegister(User *user, NickAlias *na, const Anope::string &pass) anope_override
	{
		sqli.InsertRow("create-account", na->nc->GetId(), na->nc->display);
	}

	void OnNickDrop(CommandSource &source, NickAlias *na) anope_override
	{
		if (na->nc->aliases->size() == 1 && na->nick == na->nc->display)
			sqli.InsertRow("delete-account", na->nc->GetId(), na->nc->display);
	}

	void OnChangeCoreDisplay(NickCore *nc, const Anope::string &newdisplay) anope_override
	{
		sqli.InsertRow("rename-account", nc->GetId(), newdisplay);
	}
};

MODULE_INIT(ModuleEventLog)
