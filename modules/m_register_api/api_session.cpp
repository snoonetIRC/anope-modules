#include "module.h"
#include "api_session.h"

#define INT_FIELD_SER(name) data.SetType(#name, Serialize::Data::DT_INT); data[#name] << name;

#define INT_FIELD_UNSER(name) data[#name] >> session->name;

#define SESS_FIELDS(f) f(created); \
    f(lastused); \
    f(lifetime);

#define SESSION_ID_LEN 128

Serialize::Checker<SessionMap> Session::SessionsByID(SESSION_TYPE);

Session::Session(const NickCoreRef& nickCore, time_t Lifetime)
	: Serializable(SESSION_TYPE)
	, nc(nickCore)
	, created(Anope::CurTime)
	, lastused(Anope::CurTime)
	, lifetime(Lifetime)
{
	do
	{
		id = Anope::Random(SESSION_ID_LEN);
	}
	while (Session::Find(id, false));

	(*SessionsByID)[id] = this;
}

Session::~Session()
{
	SessionsByID->erase(id);
}

void Session::Serialize(Serialize::Data& data) const
{
	data["id"] << id;
	if (nc)
		data["nc"] << nc->display;

	data.SetType("nc_id", Serialize::Data::DT_INT);
	data["nc_id"] << nc->GetId();

	SESS_FIELDS(INT_FIELD_SER)
}

Serializable* Session::Unserialize(Serializable* obj, Serialize::Data& data)
{
	Anope::string snc;
	data["nc"] >> snc;
	NickCoreRef nc = NickCore::Find(snc);
	if (!nc)
		return NULL;

	uint64_t sncid = 0;
	data["nc_id"] >> sncid;
	if (sncid && sncid != nc->GetId())
		return NULL; // New account with the same display.

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

SessionRef Session::Find(const Anope::string& id, bool touch, bool check)
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
	{
		sess->lastused = Anope::CurTime;
		sess->QueueUpdate();
	}

	return sess;
}

NickCoreRef Session::Account() const
{
	return nc;
}

bool Session::LoggedIn() const
{
	return nc;
}

bool Session::Check()
{
	if (!IsValid())
	{
		Invalidate();
		return false;
	}

	return true;
}

void Session::Invalidate()
{
	delete this;
}

bool Session::IsValid() const
{
	return (lastused + lifetime) >= Anope::CurTime;
}
