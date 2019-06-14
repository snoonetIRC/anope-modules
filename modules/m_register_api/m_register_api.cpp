#include "module.h"
#include "modules/httpd.h"
#include "third/json_api.h"
#include "third/mail_template.h"
#include "api_session.h"

#define GUEST_SUFFIX_LENGTH 7
#define STRICT_PASS_LENGTH 5
#define REG_CONFIRM_LEN 9
#define RESET_CONFIRM_LEN 20

#define DEFAULT_PASS_LEN 32

ExtensibleRef<Anope::string> passcodeExt("passcode");
ExtensibleRef<bool> unconfirmedExt("UNCONFIRMED");
ExtensibleRef<Anope::string> regserverExt("REGSERVER");

class APIRequest
	: public HTTPMessage
{
 public:
	typedef std::map<Anope::string, Anope::string> ParamMap;
	typedef Anope::string ip_t;

 private:
	const Anope::string client_id;
	const ip_t client_ip;
	const ip_t user_ip;

 public:
	SessionRef session;

	APIRequest(const APIRequest& other)
		: HTTPMessage(other)
		, client_id(other.client_id)
		, client_ip(other.client_ip)
		, user_ip(other.user_ip)
		, session(other.session)
	{
	}

	APIRequest(const HTTPMessage& message, const ip_t& ClientIP)
		: HTTPMessage(message)
		, client_id(GetParameter("client_id"))
		, client_ip(ClientIP)
		, user_ip(GetParameter("user_ip"))
	{
		Anope::string session_id;

		if (GetParameter("session", session_id))
			session = Session::Find(session_id, true, true);
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

	bool HasParameter(const ParamMap::key_type& name) const
	{
		return post_data.find(name) != post_data.end();
	}

	bool GetParameter(const ParamMap::key_type& name, ParamMap::mapped_type& value) const
	{
		ParamMap::const_iterator it = post_data.find(name);

		if (it == post_data.end())
			return false;

		value = it->second;

		return true;
	}

	ParamMap::mapped_type GetParameter(const ParamMap::key_type& name) const
	{
		ParamMap::mapped_type value;
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

struct PasswordChecker
{
	bool strictpasswords;

	unsigned passlen;

	PasswordChecker()
		: strictpasswords(true)
		, passlen(DEFAULT_PASS_LEN)
	{
	}

	bool Check(const Anope::string& username, const Anope::string& password) const
	{
		if (password.equals_ci(username))
			return false;

		if (password.length() > passlen)
			return false;

		if (strictpasswords && password.length() < STRICT_PASS_LENGTH)
			return false;

		if (password.find(' ') != Anope::string::npos)
			return false;

		return true;
	}

	void DoReload(Configuration::Conf* conf)
	{
		Configuration::Block* nickserv = conf->GetModule("nickserv");

		passlen = nickserv->Get<unsigned>("passlen", stringify(DEFAULT_PASS_LEN));

		strictpasswords = conf->GetBlock("options")->Get<bool>("strictpasswords");
	}
};

class APIEndpoint
	: public JsonAPIEndpoint
{
	typedef std::set<Anope::string> RequiredParams;
	RequiredParams required_params;
	bool need_login;

 public:
	Module* creator;

	APIEndpoint(Module* Creator, const Anope::string& u)
		: JsonAPIEndpoint(u)
		, need_login(false)
		, creator(Creator)
	{
	}

	void RequireSession()
	{
		AddRequiredParam("session");
		need_login = true;
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

		bool logged_in = request.session && request.session->LoggedIn();

		if (need_login && !logged_in)
		{
			reply.error = HTTP_BAD_REQUEST;

			JsonObject error;
			error["id"] = "no_login";
			error["message"] = "Login required";

			JsonObject responseObj;
			responseObj["status"] = "error";
			responseObj["error"] = error;

			reply.Write(responseObj.str());
			return true;
		}

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

	virtual void DoReload(Configuration::Conf* conf)
	{
	}
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
	BasicAPIEndpoint(Module* Creator, const Anope::string& u)
		: APIEndpoint(Creator, u)
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
			if (request.session && request.session->Check())
				responseObject["session"] = request.session->id;
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
	bool accessonreg;

	PasswordChecker passcheck;

	Anope::string nsregister;
	Anope::string guestnick;

	EmailTemplate regmail;

	bool SendRegmail(const NickAliasRef& na)
	{
		if (!passcodeExt)
			return false;

		NickCoreRef nc = na->nc;

		Anope::string* code = passcodeExt->Get(nc);
		if (!code)
		{
			code = passcodeExt->Set(nc);
			*code = Anope::Random(REG_CONFIRM_LEN);
		}

		EmailMessage msg = regmail.MakeMessage(na);

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

		if (nick.substr(0, guestlen).equals_ci(guestnick))
			// Nick doesn't start with the guest prefix
			return false;

		if (nick.substr(guestlen).find_first_not_of("1234567890") != Anope::string::npos)
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

	bool CheckRequest(const RegisterData& data, JsonObject& errorObject) const
	{
		if (!CheckUsername(data, errorObject))
			return false;

		if (!CheckEmail(data, errorObject))
			return false;

		if (!passcheck.Check(data.username, data.password))
		{
			errorObject["id"] = "invalid_password";
			errorObject["message"] = "That password is invalid";
			return false;
		}

		return true;
	}

 public:
	RegistrationEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "register")
		, restrictopernicks(true)
		, forceemail(true)
		, accessonreg(true)
		, regmail("registration")
	{
		AddRequiredParam("username");
		AddRequiredParam("password");
		AddRequiredParam("source");
		AddRequiredParam("user_ip");

		if (forceemail)
			AddRequiredParam("email");
	}

	void DoReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* nickserv = conf->GetModule("nickserv");

		restrictopernicks = nickserv->Get<bool>("restrictopernicks");
		forceemail = nickserv->Get<bool>("forceemail", "yes");
		guestnick = nickserv->Get<const Anope::string>("guestnickprefix", "Guest");

		nsregister = conf->GetModule("ns_register")->Get<const Anope::string>("registration");

		accessonreg = conf->GetModule("ns_access")->Get<bool>("addaccessonreg");

		regmail.DoReload(conf);
		passcheck.DoReload(conf);
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

		if (regserverExt)
			regserverExt->Set(nc, data.source);

		DoConfirm(na, data);

		FOREACH_MOD(OnNickRegister, (NULL, na, data.password));

		if (!data.ip.empty() && !data.ident.empty() && accessonreg)
			nc->AddAccess(data.ident + "@" + data.ip);

		request.session = new Session(nc);

		if (unconfirmedExt && unconfirmedExt->HasExt(nc))
		{
			responseObject["verify"] = nsregister;
			responseObject["need_verify"] = true;
		}
		else
		{
			responseObject["verify"] = "none";
			responseObject["need_verify"] = false;
		}

		return true;
	}

 private:
	void DoConfirm(NickAlias* na, const RegisterData& data)
	{
		if (!unconfirmedExt || !passcodeExt)
			return;

		if (nsregister.equals_ci("admin"))
		{
			unconfirmedExt->Set(na->nc);
		}
		else if (nsregister.equals_ci("mail"))
		{
			if (!data.email.empty())
			{
				unconfirmedExt->Set(na->nc);
				SendRegmail(na);
			}
		}
	}
};

class ConfirmEndpoint
	: public BasicAPIEndpoint
{
 public:
	ConfirmEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "confirm")
	{
		RequireSession();
		AddRequiredParam("code");
		AddRequiredParam("user_ip");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string code;

		if (!unconfirmedExt || !passcodeExt)
		{
			errorObject["id"] = "no_confirm";
			errorObject["message"] = "Account confirmation is disabled.";
			return false;
		}

		code = request.GetParameter("code");

		NickCoreRef nc = request.session->Account();

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
	Reference<HTTPClient> client;
	APIRequest request;
	APIEndpoint* endpoint;

 public:
	APIIndentifyRequest(Module* o, const Anope::string& acc, const Anope::string& pass, HTTPReply& Reply,
						const Reference<HTTPClient>& Client, const APIRequest& Request, APIEndpoint* Endpoint)
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
		obj["verified"] = !unconfirmedExt || !unconfirmedExt->HasExt(na->nc);

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
 public:
	LoginEndpoint(Module* Owner)
		: APIEndpoint(Owner, "login")
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

		APIIndentifyRequest* req = new APIIndentifyRequest(creator, user, password, reply, client, request, this);
		FOREACH_MOD(OnCheckAuthentication, (NULL, req));
		req->Dispatch();
		return false;
	}
};

class LogoutEndpoint
	: public BasicAPIEndpoint
{
 public:
	LogoutEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "logout")
	{
		RequireSession();
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		SessionRef session = request.session;

		APILogger(*this, request) << "Session logout for account: " << session->Account()->display;

		session->Invalidate();
		return true;
	}
};

class ResetPassEndpoint
	: public BasicAPIEndpoint
{
	EmailTemplate resetmail;

	bool SendResetmail(const NickAliasRef& na)
	{
		NickCoreRef nc = na->nc;

		ResetInfo* ri = resetinfo.Require(nc);
		ri->first = Anope::Random(RESET_CONFIRM_LEN);
		ri->second = Anope::CurTime;

		EmailMessage msg = resetmail.MakeMessage(na);

		msg.SetVariable("%c", ri->first);

		return Mail::Send(nc, msg.GetSubject(), msg.GetBody());
	}

 public:
	PrimitiveExtensibleItem<ResetInfo> resetinfo;

	ResetPassEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "resetpass")
		, resetmail("reset")
		, resetinfo(Creator, "reset_info")
	{
		AddRequiredParam("account");
		AddRequiredParam("email");
	}

	void DoReload(Configuration::Conf* conf) anope_override
	{
		resetmail.DoReload(conf);
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string account, email;

		account = request.GetParameter("account");
		email = request.GetParameter("email");

		NickAlias* na = NickAlias::Find(account);

		if (!na)
		{
			errorObject["id"] = "no_account";
			errorObject["message"] = "Unable to find matching account";
			return false;
		}

		NickCore* nc = na->nc;

		if (!nc->email.equals_ci(email))
		{
			errorObject["id"] = "no_account";
			errorObject["message"] = "Unable to find matching account";
			return false;
		}

		if (!SendResetmail(na))
		{
			errorObject["id"] = "mail_failed";
			errorObject["message"] = "Unable to send reset email";
			return false;
		}

		return true;
	}
};

class ResetConfirmEndpoint
	: public BasicAPIEndpoint
{
	PasswordChecker passcheck;

 public:
	PrimitiveExtensibleItem<ResetInfo>& resetinfo;

	ResetConfirmEndpoint(Module* Creator, PrimitiveExtensibleItem<ResetInfo>& Resetinfo)
		: BasicAPIEndpoint(Creator, "resetpass/confirm")
		, resetinfo(Resetinfo)
	{
		AddRequiredParam("account");
		AddRequiredParam("code");
		AddRequiredParam("newpass");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string account, code, password;

		account = request.GetParameter("account");
		code = request.GetParameter("code");
		password = request.GetParameter("mewpass");

		NickAlias* na = NickAlias::Find(account);
		NickCore* nc;

		if (na)
			nc = na->nc;
		else
			nc = NULL;

		ResetInfo* ri;
		if (!nc || !(ri = resetinfo.Get(nc)) || ri->first != code)
		{
			errorObject["id"] = "wrong_code";
			errorObject["message"] = "Invalid reset token";
			return false;
		}

		if (ri->second + 3600 < Anope::CurTime)
		{
			errorObject["id"] = "expired_code";
			errorObject["message"] = "Expired reset token";
			return false;
		}

		resetinfo.Unset(nc);

		if (!passcheck.Check(nc->display, password))
		{
			errorObject["id"] = "invalid_password";
			errorObject["message"] = "That password is invalid";
			return false;
		}

		Anope::Encrypt(password, nc->pass);

		return true;
	}

	void DoReload(Configuration::Conf* conf) anope_override
	{
		passcheck.DoReload(conf);
	}
};

class SetPasswordEndpoint
	: public BasicAPIEndpoint
{
	PasswordChecker passcheck;
 public:
	SetPasswordEndpoint(Module* Creator)
		: BasicAPIEndpoint(Creator, "user/set/password")
	{
		RequireSession();
		AddRequiredParam("newpass");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		SessionRef session = request.session;

		Anope::string password = request.GetParameter("newpass");
		NickCore* nc = session->Account();

		if (!passcheck.Check(nc->display, password))
		{
			errorObject["id"] = "invalid_password";
			errorObject["message"] = "That password is invalid";
			return false;
		}

		Anope::Encrypt(password, nc->pass);

		return true;
	}

	void DoReload(Configuration::Conf* conf) anope_override
	{
		passcheck.DoReload(conf);
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
	ResetPassEndpoint resetpass;
	ResetConfirmEndpoint resetconfirm;
	SetPasswordEndpoint setpass;

	typedef std::vector<APIEndpoint*> PageList;
	PageList pages;

 public:
	RegisterApiModule(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, session_type(SESSION_TYPE, Session::Unserialize)
		, reg(this)
		, confirm(this)
		, login(this)
		, logout(this)
		, resetpass(this)
		, resetconfirm(this, resetpass.resetinfo)
		, setpass(this)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.2");

		pages.push_back(&reg);
		pages.push_back(&confirm);
		pages.push_back(&login);
		pages.push_back(&logout);
		pages.push_back(&resetpass);
		pages.push_back(&resetconfirm);
		pages.push_back(&setpass);
	}

	void RegisterPages()
	{
		if (!httpd)
			return;

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			httpd->RegisterPage(*it);
	}

	void UnregisterPages()
	{
		if (!httpd)
			return;

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			httpd->UnregisterPage(*it);
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

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			(*it)->DoReload(conf);
	}
};

MODULE_INIT(RegisterApiModule)
