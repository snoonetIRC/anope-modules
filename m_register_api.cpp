#include "module.h"
#include "modules/httpd.h"
#include "json_api.h"

#define GUEST_SUFFIX_LENGTH 7
#define STRICT_PASS_LENGTH 5

#define SESSION_TYPE "API_Session"

struct RegisterData
{
	Anope::string username;
	Anope::string email;
	Anope::string password;
	Anope::string source;

	static RegisterData FromMessage(HTTPMessage& message)
	{
		RegisterData data;
		data.username = message.post_data["username"];
		data.email = message.post_data["email"];
		data.password = message.post_data["password"];
		data.source = message.post_data["source"];
		return data;
	}
};

struct Session;

typedef Serialize::Reference<Session> SessionRef;
typedef Serialize::Reference<NickCore> NickCoreRef;
typedef Serialize::Reference<NickAlias> NickAliasRef;
typedef Reference<HTTPClient> HTTPClientRef;

typedef std::map<const Anope::string, SessionRef> SessionMap;

Serialize::Checker<SessionMap> SessionsByID(SESSION_TYPE);
ExtensibleRef<Anope::string> passcodeExt("passcode");
ExtensibleRef<bool> unconfirmedExt("UNCONFIRMED");

#define INT_FIELD_SER(name) data.SetType(#name, Serialize::Data::DT_INT); data[#name] << name;

#define INT_FIELD_UNSER(name) data[#name] >> session->name;

#define SESS_FIELDS(f) f(created); \
    f(lastused); \
    f(lifetime);


struct Session
	: Serializable
{
	Anope::string id;
	NickCoreRef nc;

	time_t created;
	time_t lastused;
	time_t lifetime;

	Session(const NickCoreRef& nickCore, time_t Lifetime = 86400)
		: Serializable(SESSION_TYPE)
		, nc(nickCore)
		, created(Anope::CurTime)
		, lastused(Anope::CurTime)
		, lifetime(Lifetime)
	{
		do
		{
			id = Anope::Random(128);
		}
		while (Session::Find(id, false));

		(*SessionsByID)[id] = this;
	}

	~Session()
	{
		SessionsByID->erase(id);
	}

	void Serialize(Serialize::Data& data) const
	{
		data["id"] << id;
		if (nc)
			data["nc"] << nc->display;

		SESS_FIELDS(INT_FIELD_SER)
	}

	static Serializable* Unserialize(Serializable* obj, Serialize::Data& data)
	{
		Anope::string snc;
		data["nc"] >> snc;
		NickCoreRef nc = NickCore::Find(snc);
		if (!nc)
			return NULL;

		Session* session;
		if (obj)
			session = anope_dynamic_static_cast<Session*>(obj);
		else
			session = new Session(NULL);

		session->nc = nc;
		data["id"] >> session->id;

		SESS_FIELDS(INT_FIELD_UNSER)

		return session;
	}

	static SessionRef Find(const Anope::string& id, bool touch = true, bool check = true)
	{
		SessionMap::iterator it = SessionsByID->find(id);
		if (it == SessionsByID->end())
			return NULL;

		SessionRef sess = it->second;
		if (!sess)
			return NULL;

		if (check && !sess->Check())
			return NULL;

		if (touch)
			sess->lastused = Anope::CurTime;

		return sess;
	}

	NickCoreRef Account()
	{
		return nc;
	}

	bool LoggedIn() const
	{
		return nc;
	}

	bool Check()
	{
		if (!IsValid())
		{
			Invalidate();
			return false;
		}

		return true;
	}

	void Invalidate()
	{
		delete this;
	}

	bool IsValid() const
	{
		return (lastused + lifetime) >= Anope::CurTime;
	}
};

typedef Anope::string MessageT;

class EmailMessage
{
	MessageT subject;
	MessageT message;

 public:
	EmailMessage(const NickCoreRef& nc, const MessageT& Subject, const MessageT& Message)
		: subject(Language::Translate(nc, Subject.c_str()))
		, message(Language::Translate(nc, Message.c_str()))
	{
	}

	void SetVariable(const Anope::string& Name, const Anope::string& value)
	{
		subject = subject.replace_all_cs(Name, value);
		message = message.replace_all_cs(Name, value);
	}

	MessageT GetSubject()
	{
		return subject;
	}

	MessageT GetBody()
	{
		return message;
	}
};

class EmailTemplate
{
 private:
	Anope::string name;
	MessageT subject;
	MessageT message;

 public:
	EmailTemplate(const Anope::string& Name)
		: name(Name)
	{
	}

	EmailMessage MakeMessage(const NickCoreRef& nc) const
	{
		return EmailMessage(nc, subject, message);
	}

	void DoReload(Configuration::Conf* conf)
	{
		Configuration::Block* mailblock = conf->GetBlock("mail");
		subject = mailblock->Get<const MessageT>(name + "_subject");
		message = mailblock->Get<const MessageT>(name + "_message");
	}
};

class APIEndpoint
	: public JsonAPIEndpoint
{
 public:
	APIEndpoint(const Anope::string& u)
		: JsonAPIEndpoint(u)
	{
	}

	Anope::string GetEndpointID() const
	{
		return this->GetURL().substr(1);
	}

	bool OnRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
				   HTTPMessage& message, HTTPReply& reply) anope_override
	{
		Anope::string client_id, client_ip;
		client_id = message.post_data["client_id"];
		client_ip = client->GetIP();

		if (client_id.empty() || client_ip.empty())
		{
			reply.error = HTTP_BAD_REQUEST;
			return true;
		}

		Log(LOG_NORMAL, this->GetEndpointID()) << "API: " << GetEndpointID() << ": Request received from " << client_id
											   << " on " << client_ip;

		return HandleRequest(provider, string, client, message, reply);
	}

	virtual bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
							   HTTPMessage& message, HTTPReply& reply) = 0;
};

class BasicAPIEndpoint
	: public APIEndpoint
{
 public:
	BasicAPIEndpoint(const Anope::string& u)
		: APIEndpoint(u)
	{
	}

	bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client, HTTPMessage& message,
					   HTTPReply& reply) anope_override
	{
		JsonObject responseObject, errorObject;

		if (!HandleRequest(message, responseObject, errorObject))
		{
			responseObject["error"] = errorObject;
			responseObject["status"] = "error";
		}
		else
		{
			responseObject["status"] = "ok";
		}
		reply.Write(responseObject.str());

		return true;
	}

	virtual bool HandleRequest(HTTPMessage& message, JsonObject& responseObject, JsonObject& errorObject) = 0;
};

class RegistrationEndpoint
	: public BasicAPIEndpoint
{
 private:
	bool restrictopernicks;
	bool forceemail;
	bool strictpasswords;

	unsigned passlen;

	Anope::string nsregister;
	Anope::string guestnick;
	Anope::string network;

	ExtensibleRef<bool> unconfirmed;
	ExtensibleRef<Anope::string> regserver;

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
		, passlen(32)
		, unconfirmed("UNCONFIRMED")
		, regserver("REGSERVER")
		, regmail("registration")
	{
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

		network = conf->GetBlock("networkinfo")->Get<const Anope::string>("networkname");

		regmail.DoReload(conf);
	}

	bool HandleRequest(HTTPMessage& message, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		RegisterData data = RegisterData::FromMessage(message);
		if (!CheckRequest(data, errorObject))
			return false;

		NickCoreRef nc = new NickCore(data.username);
		NickAliasRef na = new NickAlias(data.username, nc);
		Anope::Encrypt(data.password, nc->pass);

		if (!data.email.empty())
			nc->email = data.email;

		na->last_realname = data.username;

		Anope::string emailStr = (!na->nc->email.empty() ? na->nc->email : "none");

		Log(LOG_NORMAL, this->GetURL().substr(1)) << "API: Account created: " << na->nick
												  << " (email: " << emailStr << ")";

		regserver->Set(nc, data.source);

		if (nsregister.equals_ci("admin"))
		{
			unconfirmed->Set(nc);
		}
		else if (nsregister.equals_ci("mail"))
		{
			if (!data.email.empty())
			{
				unconfirmed->Set(nc);
				SendRegmail(na);
			}
		}

		FOREACH_MOD(OnNickRegister, (NULL, na, data.password));

		SessionRef session = new Session(nc);

		responseObject["session"] = session->id;
		if (unconfirmed->Get(nc))
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
	}

	bool HandleRequest(HTTPMessage& message, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string code, session_id;

		code = message.post_data["code"];
		session_id = message.post_data["session"];

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

 public:
	APIIndentifyRequest(Module* o, const Anope::string& acc, const Anope::string& pass, HTTPReply& Reply,
						const HTTPClientRef& Client)
		: IdentifyRequest(o, acc, pass)
		, reply(Reply)
		, client(Client)
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
		SessionRef session = new Session(na->nc);
		JsonObject obj;
		obj["session"] = session->id;
		obj["account"] = na->nc->display;
		obj["status"] = "ok";

		OnResult(obj);
	}

	void OnFail() anope_override
	{
		JsonObject obj, error;
		error["id"] = "failed_login";
		error["message"] = "Invalid login credentials";

		obj["error"] = error;
		obj["status"] = "error";

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
	}

	bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client, HTTPMessage& message,
					   HTTPReply& reply) anope_override
	{
		Anope::string user, password;

		user = message.post_data["username"];
		password = message.post_data["password"];

		APIIndentifyRequest* req = new APIIndentifyRequest(owner, user, password, reply, client);
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
	}

	bool HandleRequest(HTTPMessage& message, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string session_id = message.post_data["session"];

		SessionRef session = Session::Find(session_id);
		if (!session || !session->LoggedIn())
		{
			errorObject["id"] = "no_login";
			errorObject["message"] = "You are not logged in to an account";
			return false;
		}

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
