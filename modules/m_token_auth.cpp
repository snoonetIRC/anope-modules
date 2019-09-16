#include "module.h"
#include "m_token_auth.h"

/*
 * TODO
 * 	add tokens with command
 * 	remove tokens with command
 * 	track active sessions using each token
 * 	command to list active sessions
 */

class ModuleTokenAuth
	: public Module
{
 public:
	ExtensibleItem<AuthTokenList> listext;
	Serialize::Type tokentype;

	ModuleTokenAuth(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, listext(this, TOKENS_EXT_NAME)
		, tokentype(TOKEN_TYPE, AuthToken::Unserialize, this)
	{
		this->SetAuthor("linuxdaemon");
		this->SetVersion("0.1");
	}

	void OnCheckAuthentication(User* u, IdentifyRequest* req) anope_override
	{
		const NickAlias* na = NickAlias::Find(req->GetAccount());
		if (!na)
			return;

		NickCore* nc = na->nc;
		AuthTokenList* tokens = listext.Get(nc);
		AuthToken* token;
		if (tokens && (token = tokens->FindToken(req->GetPassword())))
		{
			token->AddLogin(u);
			req->Success(this);
		}
	}
};

MODULE_INIT(ModuleTokenAuth)
