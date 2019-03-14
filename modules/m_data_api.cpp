#include "module.h"
#include "modules/httpd.h"
#include "json_api.h"

class UserAPI
	: public JsonAPIEndpoint
{
 public:
	UserAPI()
		: JsonAPIEndpoint("user")
	{
	}

	bool OnRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client, HTTPMessage& message,
				   HTTPReply& reply)
	{
		NickAlias* na = NickAlias::Find(message.get_data["name"]);
		JsonObject responseObject;
		if (!na)
		{
			reply.error = HTTP_PAGE_NOT_FOUND;
			responseObject["error"] = "no_user";
			reply.Write(responseObject.str());
			return true;
		}

		NickCore* nc = na->nc;
		JsonObject& aliasObj = responseObject;
		JsonSerializeData data;
		na->Serialize(data);
		data.GetJson(aliasObj);

		JsonObject actObj;

		data.Clear();
		nc->Serialize(data);
		data.GetJson(actObj);

		actObj.erase("pass");

		responseObject["nc"] = actObj;

		reply.Write(responseObject.str());
		return true;
	}
};

class DataApiModule
	: public Module
{
	ServiceReference<HTTPProvider> httpd;
	UserAPI api;

 public:
	DataApiModule(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.1");
	}

	~DataApiModule() anope_override
	{
		if (httpd)
			httpd->UnregisterPage(&api);
	}

	void OnReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* block = conf->GetModule(this);
		if (httpd)
			httpd->UnregisterPage(&api);

		const Anope::string provider = block->Get<const Anope::string>("server", "httpd/main");
		this->httpd = ServiceReference<HTTPProvider>("HTTPProvider", provider);
		if (!httpd)
			throw ConfigException("Unable to find http reference, is m_httpd loaded?");

		httpd->RegisterPage(&api);
	}
};

MODULE_INIT(DataApiModule)
