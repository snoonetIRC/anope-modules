#include "module.h"
#include "modules/httpd.h"
#include "json_api.h"
#include "mail_template.h"
#include "api_session.h"

#define GUEST_SUFFIX_LENGTH 7
#define STRICT_PASS_LENGTH 5

class APIRequest
	: public HTTPMessage
{
 public:
	typedef Anope::string data_value_type;
	typedef Anope::string ip_t;

 private:
	const Anope::string client_id;
	const ip_t client_ip;
	const ip_t user_ip;

 public:
	APIRequest(const APIRequest& other)
		: HTTPMessage(other)
		, client_id(other.client_id)
		, client_ip(other.client_ip)
		, user_ip(other.user_ip)
	{
	}

	explicit APIRequest(const HTTPMessage& message, const ip_t& ClientIP)
		: HTTPMessage(message)
		, client_id(GetParameter("client_id"))
		, client_ip(ClientIP)
		, user_ip(GetParameter("user_ip"))
	{
	}

	virtual ~APIRequest()
	{
	}

	const Anope::string& getClientId() const
	{
		return client_id;
	}

	const ip_t& getClientIp() const
	{
		return client_ip;
	}

	const ip_t& getUserIp() const
	{
		return user_ip;
	}

	bool IsValid() const
	{
		return !(client_id.empty() || client_ip.empty());
	}

	bool HasParameter(const Anope::string& name) const
	{
		return post_data.find(name) != post_data.end();
	}

	bool GetParameter(const Anope::string& name, data_value_type& value) const
	{
		std::map<Anope::string, Anope::string>::const_iterator it = post_data.find(name);

		if (it == post_data.end())
			return false;

		value = it->second;

		return true;
	}

	data_value_type GetParameter(const Anope::string& name) const
	{
		data_value_type value;
		GetParameter(name, value);
		return value;
	}
};

struct RegisterData
{
	Anope::string username;
	Anope::string email;
	Anope::string password;
	Anope::string source;
	Anope::string ident;
	Anope::string ip;

	static RegisterData FromMessage(APIRequest& request)
	{
		RegisterData data;
		data.username = request.GetParameter("username");
		data.ident = request.GetParameter("ident");
		data.ip = request.getUserIp();
		data.email = request.GetParameter("email");
		data.password = request.GetParameter("password");
		data.source = request.GetParameter("source");
		return data;
	}
};

class APIEndpoint
	: public JsonAPIEndpoint
{
	typedef std::set<Anope::string> RequiredParams;
	RequiredParams required_params;

 public:
	APIEndpoint(const Anope::string& u)
		: JsonAPIEndpoint(u)
	{
	}

	void AddRequiredParam(const Anope::string& name)
	{
		required_params.insert(name);
	}

	Anope::string GetEndpointID() const
	{
		return this->GetURL().substr(1);
	}

	bool OnRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
				   HTTPMessage& message, HTTPReply& reply) anope_override
	{
		APIRequest request(message, client->GetIP());

		if (!request.IsValid())
		{
			reply.error = HTTP_BAD_REQUEST;
			return true;
		}

		JsonArray missing;

		for (RequiredParams::const_iterator it = required_params.begin(); it != required_params.end(); ++it)
		{
			if (request.GetParameter(*it).empty())
				missing.push_back(*it);
		}

		if (!missing.empty())
		{
			reply.error = HTTP_BAD_REQUEST;

			JsonObject error;
			error["id"] = "missing_parameters";
			error["message"] = "Missing required request parameters";
			error["parameters"] = missing;

			JsonObject responseObj;
			responseObj["status"] = "error";
			responseObj["error"] = error;

			reply.Write(responseObj.str());
			return true;
		}

		Log(LOG_NORMAL, this->GetEndpointID()) << "API: " << GetEndpointID() << ": Request received from "
											   << request.getClientId() << " on " << request.getClientIp();

		return HandleRequest(provider, string, client, request, reply);
	}

	virtual bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
							   APIRequest& request, HTTPReply& reply) = 0;
};

class APILogger
	: public Log
{
 public:
	APILogger(const APIEndpoint& endpoint, const APIRequest& request)
		: Log(LOG_NORMAL, endpoint.GetURL().substr(1))
	{
		*this << "API: " << category << " from " << request.getClientId()
			  << " on " << request.getClientIp();

		if (!request.getUserIp().empty())
			*this << " (user: " << request.getUserIp() << ")";

		*this << ": ";
	}
};

class BasicAPIEndpoint
	: public APIEndpoint
{
 public:
	BasicAPIEndpoint(const Anope::string& u)
		: APIEndpoint(u)
	{
	}

	bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client, APIRequest& request,
					   HTTPReply& reply) anope_override
	{
		JsonObject responseObject, errorObject;

		if (!HandleRequest(request, responseObject, errorObject))
		{
			responseObject["error"] = errorObject;
			responseObject["status"] = "error";

			APILogger(*this, request) << "Error: " << errorObject["id"].str();
		}
		else
		{
			responseObject["status"] = "ok";
		}
		reply.Write(responseObject.str());

		return true;
	}

	virtual bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) = 0;
};

class RegistrationEndpoint
	: public BasicAPIEndpoint
{
 private:
	bool restrictopernicks;
	bool forceemail;
	bool strictpasswords;
	bool accessonreg;

	unsigned passlen;

	Anope::string nsregister;
	Anope::string guestnick;
	Anope::string network;

	EmailTemplate regmail;

	bool SendRegmail(const NickAliasRef& na)
	{
		NickCoreRef nc = na->nc;

		Anope::string* code = passcodeExt->Get(nc);
		if (!code)
		{
			code = passcodeExt->Set(nc);
			*code = Anope::Random(9);
		}

		EmailMessage msg = regmail.MakeMessage(nc);

		msg.SetVariable("%n", na->nick);
		msg.SetVariable("%N", network);
		msg.SetVariable("%c", *code);

		return Mail::Send(nc, msg.GetSubject(), msg.GetBody());
	}

	bool IsOperNick(const Anope::string& nick) const
	{
		for (std::vector<Oper*>::const_iterator i = Oper::opers.begin(); i != Oper::opers.end(); ++i)
		{
			if (nick.find_ci((*i)->name) != Anope::string::npos)
			{
				return true;
			}
		}
		return false;
	}

	bool IsGuest(const Anope::string& nick) const
	{
		Anope::string::size_type nicklen, guestlen;

		nicklen = nick.length();
		guestlen = guestnick.length();

		if (nicklen > (guestlen + GUEST_SUFFIX_LENGTH))
			// Nick is longer than the possible guest nick
			return false;

		if (nicklen <= guestlen)
			// Nick is shorter than the shortest possible guest nick
			return false;

		if (nick.substr(0, guestlen) != guestnick)
			// Nick doesn't start with the guest prefix
			return false;

		if (nick.substr(guestnick.length()).find_first_not_of("1234567890") != Anope::string::npos)
			// Nick contains non-digits after guest prefix
			return false;

		return true;
	}

	bool CheckUsername(const RegisterData& data, JsonObject& errorObject) const
	{
		if (User::Find(data.username) || BotInfo::Find(data.username, true) ||
			(restrictopernicks && IsOperNick(data.username)))
		{
			errorObject["id"] = "name_in_use";
			errorObject["message"] = "This username is in use by another user and can not be registered";
			return false;
		}

		if (NickCore::Find(data.username))
		{
			errorObject["id"] = "user_exists";
			errorObject["message"] = "A user with that name is already registered";
			return false;
		}

		if (IsGuest(data.username))
		{
			errorObject["id"] = "no_guest";
			errorObject["message"] = "Guest nicknames may not be registered";
			return false;
		}

		if (!IRCD->IsNickValid(data.username))
		{
			errorObject["id"] = "invalid_name";
			errorObject["message"] = "Username is invalid";
			return false;
		}
		return true;
	}

	bool CheckEmail(const RegisterData& data, JsonObject& errorObject) const
	{
		if (data.email.empty())
		{
			if (forceemail)
			{
				errorObject["id"] = "missing_email";
				errorObject["message"] = "An email address is required for registration";
				return false;
			}

			// If forceemail = false, an empty email is valid
			return true;
		}

		if (!Mail::Validate(data.email))
		{
			errorObject["id"] = "invalid_email";
			errorObject["message"] = "A valid email address is required for registration";
			return false;
		}

		return true;
	}

	bool CheckPassword(const RegisterData& data, JsonObject& errorObject) const
	{
		if (data.password.equals_ci(data.username))
			return false;

		if (data.password.length() > passlen)
			return false;

		if (strictpasswords && data.password.length() < STRICT_PASS_LENGTH)
			return false;

		return true;
	}

	bool CheckRequest(const RegisterData& data, JsonObject& errorObject) const
	{
		if (!CheckUsername(data, errorObject))
			return false;

		if (!CheckEmail(data, errorObject))
			return false;

		if (!CheckPassword(data, errorObject))
		{
			errorObject["id"] = "invalid_password";
			errorObject["message"] = "That password is invalid";
			return false;
		}

		return true;
	}

 public:
	RegistrationEndpoint()
		: BasicAPIEndpoint("register")
		, restrictopernicks(true)
		, forceemail(true)
		, strictpasswords(true)
		, accessonreg(true)
		, passlen(32)
		, regmail("registration")
	{
		AddRequiredParam("username");
		AddRequiredParam("password");
		AddRequiredParam("source");
		AddRequiredParam("user_ip");

		if (forceemail)
			AddRequiredParam("email");
	}

	void OnReload(Configuration::Conf* conf)
	{
		Configuration::Block* nickserv = conf->GetModule("nickserv");

		restrictopernicks = nickserv->Get<bool>("restrictopernicks");
		forceemail = nickserv->Get<bool>("forceemail", "yes");
		passlen = nickserv->Get<unsigned>("passlen", "32");
		guestnick = nickserv->Get<const Anope::string>("guestnickprefix", "Guest");

		strictpasswords = conf->GetBlock("options")->Get<bool>("strictpasswords");

		nsregister = conf->GetModule("ns_register")->Get<const Anope::string>("registration");

		accessonreg = conf->GetModule("ns_access")->Get<bool>("addaccessonreg");

		network = conf->GetBlock("networkinfo")->Get<const Anope::string>("networkname");

		regmail.DoReload(conf);
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		RegisterData data = RegisterData::FromMessage(request);
		if (!CheckRequest(data, errorObject))
			return false;

		NickCoreRef nc = new NickCore(data.username);
		NickAliasRef na = new NickAlias(data.username, nc);
		Anope::Encrypt(data.password, nc->pass);

		if (!data.email.empty())
			nc->email = data.email;

		na->last_realname = data.username;

		Anope::string emailStr = (!na->nc->email.empty() ? na->nc->email : "none");

		APILogger(*this, request) << "Account created: " << nc->display
								  << " (email: " << emailStr << ")";

		regserverExt->Set(nc, data.source);

		if (nsregister.equals_ci("admin"))
		{
			unconfirmedExt->Set(nc);
		}
		else if (nsregister.equals_ci("mail"))
		{
			if (!data.email.empty())
			{
				unconfirmedExt->Set(nc);
				SendRegmail(na);
			}
		}

		FOREACH_MOD(OnNickRegister, (NULL, na, data.password));

		if (!data.ip.empty() && !data.ident.empty() && accessonreg)
			nc->AddAccess(data.ident + "@" + data.ip);

		SessionRef session = new Session(nc);

		responseObject["session"] = session->id;
		if (unconfirmedExt->Get(nc))
		{
			responseObject["verify"] = nsregister;
		}

		return true;
	}
};

class ConfirmEndpoint
	: public BasicAPIEndpoint
{
 public:
	ConfirmEndpoint()
		: BasicAPIEndpoint("confirm")
	{
		AddRequiredParam("session");
		AddRequiredParam("code");
		AddRequiredParam("user_ip");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string code, session_id;

		code = request.GetParameter("code");
		session_id = request.GetParameter("session");

		SessionRef session = Session::Find(session_id);
		if (!session || !session->LoggedIn())
		{
			errorObject["id"] = "no_login";
			errorObject["message"] = "You are not logged in to an account";
			return false;
		}

		responseObject["session"] = session->id;

		NickCoreRef nc = session->Account();

		if (!unconfirmedExt->HasExt(nc))
		{
			errorObject["id"] = "already_confirmed";
			errorObject["message"] = "This account is already confirmed";
			return false;
		}

		Anope::string* nc_code = passcodeExt->Get(nc);

		if (!nc_code || code != *nc_code)
		{
			errorObject["id"] = "wrong_code";
			errorObject["message"] = "Incorrect confirmation code supplied";
			return false;
		}

		APILogger(*this, request) << "Account confirmed: " << nc->display;

		unconfirmedExt->Unset(nc);
		passcodeExt->Unset(nc);
		return true;
	}
};

class APIIndentifyRequest
	: public IdentifyRequest
{
 private:
	HTTPReply reply;
	HTTPClientRef client;
	APIRequest request;
	APIEndpoint* endpoint;

 public:
	APIIndentifyRequest(Module* o, const Anope::string& acc, const Anope::string& pass, HTTPReply& Reply,
						const HTTPClientRef& Client, const APIRequest& Request, APIEndpoint* Endpoint)
		: IdentifyRequest(o, acc, pass)
		, reply(Reply)
		, client(Client)
		, request(Request)
		, endpoint(Endpoint)
	{
	}

	void OnResult(const JsonObject& obj)
	{
		reply.Write(obj.str());
		client->SendReply(&reply);
	}

	void OnSuccess() anope_override
	{
		NickAliasRef na = NickAlias::Find(GetAccount());
		if (!na)
			return OnFail();

		SessionRef session = new Session(na->nc);
		JsonObject obj;
		obj["session"] = session->id;
		obj["account"] = na->nc->display;
		obj["status"] = "ok";

		APILogger(*endpoint, request) << "Account login: " << na->nc->display;

		OnResult(obj);
	}

	void OnFail() anope_override
	{
		JsonObject obj, error;
		error["id"] = "failed_login";
		error["message"] = "Invalid login credentials";

		obj["error"] = error;
		obj["status"] = "error";

		APILogger(*endpoint, request) << "Failed account login: " << GetAccount();

		OnResult(obj);
	}
};

class LoginEndpoint
	: public APIEndpoint
{
 private:
	Module* owner;

 public:
	LoginEndpoint(Module* Owner)
		: APIEndpoint("login")
		, owner(Owner)
	{
		AddRequiredParam("username");
		AddRequiredParam("password");
		AddRequiredParam("user_ip");
	}

	bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client, APIRequest& request,
					   HTTPReply& reply) anope_override
	{
		Anope::string user, password;

		user = request.GetParameter("username");
		password = request.GetParameter("password");

		APIIndentifyRequest* req = new APIIndentifyRequest(owner, user, password, reply, client, request, this);
		FOREACH_MOD(OnCheckAuthentication, (NULL, req));
		req->Dispatch();
		return false;
	}
};

class LogoutEndpoint
	: public BasicAPIEndpoint
{
 public:
	LogoutEndpoint()
		: BasicAPIEndpoint("logout")
	{
		AddRequiredParam("session");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string session_id = request.GetParameter("session");

		SessionRef session = Session::Find(session_id);
		if (!session || !session->LoggedIn())
		{
			errorObject["id"] = "no_login";
			errorObject["message"] = "You are not logged in to an account";
			return false;
		}

		APILogger(*this, request) << "Session logout for account: " << session->Account()->display;

		session->Invalidate();
		return true;
	}
};

class RegisterApiModule
	: public Module
{
	ServiceReference<HTTPProvider> httpd;
	Serialize::Type session_type;

	RegistrationEndpoint reg;
	ConfirmEndpoint confirm;
	LoginEndpoint login;
	LogoutEndpoint logout;

 public:
	RegisterApiModule(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, session_type(SESSION_TYPE, Session::Unserialize)
		, login(this)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.1");
	}

	void RegisterPages()
	{
		if (!httpd)
			return;

		httpd->RegisterPage(&reg);
		httpd->RegisterPage(&confirm);
		httpd->RegisterPage(&login);
		httpd->RegisterPage(&logout);
	}

	void UnregisterPages()
	{
		if (!httpd)
			return;

		httpd->UnregisterPage(&reg);
		httpd->UnregisterPage(&confirm);
		httpd->UnregisterPage(&login);
		httpd->UnregisterPage(&logout);
	}

	~RegisterApiModule() anope_override
	{
		UnregisterPages();
	}

	void OnReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* block = conf->GetModule(this);
		UnregisterPages();

		const Anope::string provider = block->Get<const Anope::string>("server", "httpd/main");
		this->httpd = ServiceReference<HTTPProvider>("HTTPProvider", provider);
		if (!httpd)
			throw ConfigException("Unable to find http reference, is m_httpd loaded?");

		if (!httpd->IsSSL())
			throw ConfigException("Registration API http must support SSL");

		RegisterPages();

		reg.OnReload(conf);
	}
};

MODULE_INIT(RegisterApiModule)
