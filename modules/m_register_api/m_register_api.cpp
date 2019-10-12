#include "module.h"
#include "modules/os_forbid.h"
#include "modules/httpd.h"
#include "third/json_api.h"
#include "third/mail_template.h"
#include "third/m_token_auth.h"
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
	bool force_confirm;

	RegisterData() : force_confirm(false) {}

	static RegisterData FromMessage(APIRequest& request)
	{
		RegisterData data;
		data.username = request.GetParameter("username");
		data.ident = request.GetParameter("ident");
		data.ip = request.getUserIp();
		data.email = request.GetParameter("email");
		data.password = request.GetParameter("password");
		data.source = request.GetParameter("source");
		data.force_confirm = request.GetParameter("force_confirm") == "1";
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

class APIEndpoint;

class APILogger
	: public Log
{
 public:
	APILogger(const APIEndpoint& endpoint, const APIRequest& request);
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

		APILogger(*this, request) << "Request received";

		return HandleRequest(provider, string, client, request, reply);
	}

	virtual bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
							   APIRequest& request, HTTPReply& reply) = 0;

	virtual void DoReload(Configuration::Conf* conf)
	{
	}
};

APILogger::APILogger(const APIEndpoint& endpoint, const APIRequest& request)
	: Log(LOG_NORMAL, endpoint.GetEndpointID())
{
	*this << "API: " << category << " from " << request.getClientId()
		  << " on " << request.getClientIp();

	if (!request.getUserIp().empty())
		*this << " (user: " << request.getUserIp() << ")";

	*this << ": ";
}

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
	ServiceReference<ForbidService> forbidService;

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

	bool CheckUsername(const RegisterData& data, JsonObject& errorObject)
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

		if (forbidService)
		{
			ForbidData* nickforbid = forbidService->FindForbid(data.username, FT_NICK);
			ForbidData* regforbid = forbidService->FindForbid(data.username, FT_REGISTER);
			if (nickforbid || regforbid)
			{
				errorObject["id"] = "forbidden_user";
				errorObject["message"] = "This nickname is forbidden from registration";
				return false;
			}
		}

		return true;
	}

	bool CheckEmail(const RegisterData& data, JsonObject& errorObject)
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

		if (forbidService)
		{
			ForbidData* f = this->forbidService->FindForbid(data.email, FT_EMAIL);
			if (f)
			{
				errorObject["id"] = "forbidden_email";
				errorObject["message"] = "This email address is forbidden";
				return false;
			}
		}

		return true;
	}

	bool CheckRequest(const RegisterData& data, JsonObject& errorObject)
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
		, forbidService("ForbidService", "forbid")
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

		if (!data.force_confirm)
		{
			DoConfirm(na, data);
		}
		else
		{
			APILogger(*this, request) << "Account " << nc->display << " confirmed via OAuth";
		}

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
			APILogger(*this, request) << "Attempt to reset password for non-existent account '" << account << "'";

		if (na && !na->nc->email.equals_ci(email))
		{
			APILogger(*this, request) << "Incorrect email (" << email
									  << ") for account '" << na->nc->display << "'";
			na = NULL;
		}

		if (na && !SendResetmail(na))
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
	const PasswordChecker& passcheck;

 public:
	PrimitiveExtensibleItem<ResetInfo>& resetinfo;

	ResetConfirmEndpoint(Module* Creator, PrimitiveExtensibleItem<ResetInfo>& Resetinfo, const PasswordChecker& Checker)
		: BasicAPIEndpoint(Creator, "resetpass/confirm")
		, passcheck(Checker)
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
		password = request.GetParameter("newpass");

		NickAlias* na = NickAlias::Find(account);
		NickCore* nc;

		if (na)
			nc = na->nc;
		else
		{
			APILogger(*this, request) << "Attempt to confirm a request for a non-existent account '" << account << "'";
			nc = NULL;
		}

		ResetInfo* ri;
		if (!nc || !(ri = resetinfo.Get(nc)) || ri->first != code)
		{
			if (nc)
				APILogger(*this, request) << "Attempt to confirm a request for '" << account << "' with an invalid code";

			errorObject["id"] = "wrong_code";
			errorObject["message"] = "Invalid reset token";
			return false;
		}

		if (ri->second + 3600 < Anope::CurTime)
		{
			APILogger(*this, request) << "Attempt to confirm a request for '" << account << "' with an expired code";
			errorObject["id"] = "expired_code";
			errorObject["message"] = "Expired reset token";
			return false;
		}

		if (!passcheck.Check(nc->display, password))
		{
			errorObject["id"] = "invalid_password";
			errorObject["message"] = "That password is invalid";
			return false;
		}

		Anope::Encrypt(password, nc->pass);

		resetinfo.Unset(nc);

		return true;
	}
};

class SetPasswordEndpoint
	: public BasicAPIEndpoint
{
	const PasswordChecker& passcheck;
 public:
	SetPasswordEndpoint(Module* Creator, const PasswordChecker& Checker)
		: BasicAPIEndpoint(Creator, "user/set/password")
		, passcheck(Checker)
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
};

class TokenEndpoint
	: public BasicAPIEndpoint
{
 public:
	TokenEndpoint(Module* Creator, const Anope::string& name)
		: BasicAPIEndpoint(Creator, "user/token/" + name)
	{
		RequireSession();
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		SessionRef session = request.session;
		NickCore* nc = session->Account();

		AuthTokenList* tokens = GetTokenList(nc, true);
		if (!tokens)
		{
			errorObject["id"] = "tokens_disabled";
			errorObject["message"] = "Token authentication appears to be disabled";
			return false;
		}

		return HandleTokenRequest(request, responseObject, errorObject, tokens);
	}

	virtual bool HandleTokenRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject, AuthTokenList* tokens) = 0;
};

class AddTokenEndpoint
	: public TokenEndpoint
{
 public:
	AddTokenEndpoint(Module* Creator)
		: TokenEndpoint(Creator, "add")
	{
		AddRequiredParam("name");
	}

	bool HandleTokenRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject, AuthTokenList* tokens) anope_override
	{
		Anope::string name = request.GetParameter("name");
		AuthToken* token = tokens->NewToken(name);

		if (!token)
		{
			errorObject["id"] = "token_add_failed";
			errorObject["message"] = "Unable to add token";
			APILogger(*this, request) << "Attempt to add duplicate tokens to account: " << request.session->nc->display;
			return false;
		}

		JsonObject tokenjson;
		tokenjson["name"] = token->GetName();
		tokenjson["token"] = token->GetToken();

		responseObject["token"] = tokenjson;

		return true;
	}
};

class DeleteTokenEndpoint
	: public TokenEndpoint
{
 public:
	DeleteTokenEndpoint(Module* Creator)
		: TokenEndpoint(Creator, "delete")
	{
		AddRequiredParam("id");
	}

	bool HandleTokenRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject, AuthTokenList* tokens) anope_override
	{
		Anope::string id = request.GetParameter("id");
		AuthToken* token = tokens->FindToken(id);
		if (!token)
		{
			try
			{
				token = tokens->GetToken(convertTo<int>(id) - 1);
			}
			catch (ConvertException& e)
			{
				// If the id isn't a number, just fall through to the normal error response
			}
		}

		if (!token)
		{
			errorObject["id"] = "no_token";
			errorObject["message"] = "No matching token found.";
			return false;
		}

		delete token;
		return true;
	}
};

class ListTokensEndpoint
	: public TokenEndpoint
{
 public:
	ListTokensEndpoint(Module* Creator)
		: TokenEndpoint(Creator, "list")
	{
	}

	bool HandleTokenRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject, AuthTokenList* tokens) anope_override
	{
		JsonArray tokenlist;
		AuthToken* t;
		for (long i = 0; (t = tokens->GetToken(i)); ++i)
		{
			JsonObject tokenObj;

			tokenObj["name"] = t->GetName();
			tokenObj["token"] = t->GetToken();
			tokenObj["id"] = i + 1;

			tokenlist.push_back(tokenObj);
		}

		responseObject["tokens"] = tokenlist;
		return true;
	}
};

class RegisterApiModule
	: public Module
{
	ServiceReference<HTTPProvider> httpd;
	Serialize::Type session_type;

	PasswordChecker passcheck;

	RegistrationEndpoint reg;
	ConfirmEndpoint confirm;
	LoginEndpoint login;
	LogoutEndpoint logout;
	ResetPassEndpoint resetpass;
	ResetConfirmEndpoint resetconfirm;
	SetPasswordEndpoint setpass;
	AddTokenEndpoint addtoken;
	DeleteTokenEndpoint deltoken;
	ListTokensEndpoint listtoken;

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
		, resetconfirm(this, resetpass.resetinfo, passcheck)
		, setpass(this, passcheck)
		, addtoken(this)
		, deltoken(this)
		, listtoken(this)
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
		pages.push_back(&addtoken);
		pages.push_back(&deltoken);
		pages.push_back(&listtoken);
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
