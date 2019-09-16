#ifndef ANOPE_M_TOKEN_AUTH_H
#define ANOPE_M_TOKEN_AUTH_H

#define TOKENS_EXT_NAME "AUTH_TOKENS"
#define TOKEN_TYPE "AUTH_TOKEN"
#define TOKEN_LEN 32

class AuthToken
	: public Serializable
{
 private:
	Anope::string name;
	Anope::string token;

	void Update();

 public:
	Serialize::Reference<NickCore> nc;
	time_t set_at;
	time_t last_used;

	typedef Anope::hash_map<Reference<User> > sesslist;

	sesslist users;

	AuthToken()
		: Serializable(TOKEN_TYPE)
		, set_at(Anope::CurTime)
		, last_used(0)
	{
	}

	AuthToken(NickCore* core, const Anope::string& Name, const Anope::string& Token)
		: Serializable(TOKEN_TYPE)
		, name(Name)
		, token(Token)
		, nc(core)
		, set_at(Anope::CurTime)
		, last_used(0)
	{
	}

	AuthToken(NickCore* core, const Anope::string& Name, const Anope::string& Token, time_t settime)
		: Serializable(TOKEN_TYPE)
		, name(Name)
		, token(Token)
		, nc(core)
		, set_at(settime)
		, last_used(0)
	{
	}

	~AuthToken() anope_override;

	void SetName(const Anope::string& string)
	{
		this->name = string;
		this->Update();
	}

	Anope::string GetName() const
	{
		return name;
	}

	void SetToken(const Anope::string& string)
	{
		this->token = string;
		this->Update();
	}

	Anope::string GetToken() const
	{
		return token;
	}

	void Serialize(Serialize::Data& data) const anope_override;

	static Serializable* Unserialize(Serializable* obj, Serialize::Data& data);

	bool AddLogin(User* u);

	/**
	 * Remove invalid User references from the session list
	 */
	void CleanUsers();

	sesslist& GetActiveSessions()
	{
		CleanUsers();
		return users;
	}
};

class AuthTokenList
{
	typedef Anope::hash_map<AuthToken*> tokenmap;
	typedef std::vector<AuthToken*> tokenlist;

	tokenmap tokens;
	tokenmap name_map;
	tokenlist list;

	Serialize::Reference<NickCore> nc;

 public:
	AuthTokenList(Extensible* extensible)
		: nc(anope_dynamic_static_cast<NickCore*>(extensible))
	{
	}

	AuthToken* NewToken(const Anope::string& name);

	bool AddToken(AuthToken* token);

	void DelToken(AuthToken* token);

	AuthToken* FindToken(const Anope::string& token);

	AuthToken* GetToken(const Anope::string& name) const;

	AuthToken* GetToken(unsigned pos) const;

	void Clear();

	void UpdateToken(const Serialize::Reference<AuthToken>& token);

	bool IsEmpty() const
	{
		return tokens.empty();
	}

	unsigned int GetSize()
	{
		return list.size();
	}
};

ExtensibleRef<AuthTokenList> GetTokenExtRef()
{
	ExtensibleRef<AuthTokenList> extRef(TOKENS_EXT_NAME);
	return extRef;
}

AuthTokenList* GetTokenList(NickCore* nc, bool create = false)
{
	ExtensibleRef<AuthTokenList> extRef(TOKENS_EXT_NAME);
	if (!extRef)
		return NULL;

	if (create)
		return extRef->Require(nc);

	return extRef->Get(nc);
}


void AuthTokenList::Clear()
{
	for (tokenlist::iterator it = list.begin(); it != list.end();)
	{
		tokenlist::iterator oldit = it++;
		delete *oldit;
	}
}

void AuthTokenList::UpdateToken(const Serialize::Reference<AuthToken>& token)
{
	this->DelToken(token);
	this->AddToken(token);
}

AuthToken* AuthTokenList::GetToken(unsigned pos) const
{
	if (pos >= list.size())
		return NULL;

	return list[pos];
}

AuthToken* AuthTokenList::GetToken(const Anope::string& name) const
{
	tokenmap::const_iterator it = name_map.find(name);
	if (it == name_map.end())
		return NULL;

	return it->second;
}

void AuthTokenList::DelToken(AuthToken* token)
{
	tokens.erase(token->GetToken());
	name_map.erase(token->GetName());
	tokenlist::iterator it = std::find(list.begin(), list.end(), token);
	if (it != list.end())
		list.erase(it);
}

AuthToken* AuthTokenList::FindToken(const Anope::string& token)
{
	tokenmap::iterator it = tokens.find(token);
	if (it == tokens.end())
		return NULL;

	return it->second;
}

bool AuthTokenList::AddToken(AuthToken* token)
{
	if (!tokens.insert(std::make_pair(token->GetToken(), token)).second)
		return false;

	if (!name_map.insert(std::make_pair(token->GetName(), token)).second)
	{
		tokens.erase(token->GetToken());
		return false;
	}

	list.push_back(token);
	return true;
}

AuthToken* AuthTokenList::NewToken(const Anope::string& name)
{
	AuthToken* t = new AuthToken(nc, name, Anope::Random(TOKEN_LEN));

	if (!this->AddToken(t))
	{
		delete t;
		return NULL;
	}

	t->QueueUpdate();
	return t;
}

Serializable* AuthToken::Unserialize(Serializable* obj, Serialize::Data& data)
{
	ExtensibleRef<AuthTokenList> extRef(TOKENS_EXT_NAME);
	Anope::string disp, name, token;
	time_t settime;

	data["nc"] >> disp;
	data["name"] >> name;
	data["token"] >> token;
	data["set_at"] >> settime;

	NickCore* nc = NickCore::Find(disp);
	if (!nc)
		return NULL;

	AuthToken* tkn;

	if (obj)
	{
		tkn = anope_dynamic_static_cast<AuthToken*>(obj);
		if (name != tkn->GetName())
			tkn->SetName(name);

		if (token != tkn->GetToken())
			tkn->SetToken(token);

		tkn->set_at = settime;
	}
	else
	{
		tkn = new AuthToken(nc, name, token, settime);
	}

	data["last_used"] >> tkn->last_used;

	if (!obj)
		extRef->Require(nc)->AddToken(tkn);

	return tkn;
}

AuthToken::~AuthToken()
{
	AuthTokenList* tokens;
	if (nc && (tokens = GetTokenList(nc)))
		tokens->DelToken(this);
}

void AuthToken::Update()
{
	GetTokenList(nc, true)->UpdateToken(this);
}

void AuthToken::Serialize(Serialize::Data& data) const
{
	data["nc"] << nc->display;
	data["name"] << GetName();
	data["token"] << GetToken();

	data.SetType("set_at", Serialize::Data::DT_INT);
	data["set_at"] << set_at;

	data.SetType("last_used", Serialize::Data::DT_INT);
	data["last_used"] << last_used;
}

bool AuthToken::AddLogin(User* u)
{
	if (u)
	{
		users.insert(std::make_pair(u->nick, u));
	}
	else
	{
		Log(LOG_NORMAL, "tokenauth/addlogin") << "AUTHTOKEN: Login added for account " << nc->display << " with no User information";
		// TODO this is probably a web or API login, find some other way to store the session
	}
	last_used = Anope::CurTime;
	this->QueueUpdate();
	return true;
}

void AuthToken::CleanUsers()
{
	for (sesslist::iterator it = users.begin(); it != users.end();)
	{
		if (!it->second)
			it = users.erase(it);
		else
			++it;
	}
}

#endif //ANOPE_M_TOKEN_AUTH_H
