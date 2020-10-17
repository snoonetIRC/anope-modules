#ifndef ANOPE_API_SESSION_H
#define ANOPE_API_SESSION_H

#include "third/snoo_types.h"

#define SESSION_LIFETIME 604800
#define SESSION_TYPE "API_Session"

struct Session;

typedef Serialize::Reference<Session> SessionRef;
typedef std::map<const Anope::string, SessionRef> SessionMap;

struct Session
	: Serializable
{
 private:
	static Serialize::Checker<SessionMap> SessionsByID;

 public:
	Anope::string id;
	NickCoreRef nc;

	time_t created;
	time_t lastused;
	time_t lifetime;

	Session(const NickCoreRef& nickCore, time_t Lifetime = SESSION_LIFETIME);

	~Session();

	void Serialize(Serialize::Data& data) const;

	static Serializable* Unserialize(Serializable* obj, Serialize::Data& data);

	static SessionRef Find(const Anope::string& id, bool touch = true, bool check = true);

	NickCoreRef Account() const;

	bool LoggedIn() const;

	bool Check();

	void Invalidate();

	bool IsValid() const;
};

#endif //ANOPE_API_SESSION_H
