#include "module.h"
#include "m_token_auth.h"

/*
 * TODO
 * 	add tokens with command
 * 	remove tokens with command
 * 	track active sessions using each token
 * 	command to list active sessions
 */

// Messages
#define TOKEN_NAME_CONFLICT "A token with that name already exists."
#define TOKEN_ADDED "Token successfully added."
#define TOKEN_LIST_EMPTY "Authentication token list is empty."
#define TOKEN_NO_MATCH "No matching authentication tokens found"
#define TOKEN_DELETED "Deleted 1 authentication token."
#define TOKEN_DELETED_MULTI "Deleted %d authentication tokens."

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
