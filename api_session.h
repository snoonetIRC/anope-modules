#ifndef ANOPE_API_SESSION_H
#define ANOPE_API_SESSION_H

#include "snoo_types.h"

#define INT_FIELD_SER(name) data.SetType(#name, Serialize::Data::DT_INT); data[#name] << name;

#define INT_FIELD_UNSER(name) data[#name] >> session->name;

#define SESS_FIELDS(f) f(created); \
    f(lastused); \
    f(lifetime);

#define SESSION_TYPE "API_Session"


struct Session;


typedef Serialize::Reference<Session> SessionRef;
typedef std::map<const Anope::string, SessionRef> SessionMap;

Serialize::Checker<SessionMap> SessionsByID(SESSION_TYPE);


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

#endif //ANOPE_API_SESSION_H
