#ifndef ANOPE_MAIL_TEMPLATE_H
#define ANOPE_MAIL_TEMPLATE_H

typedef Anope::string MessageT;

class EmailMessage
{
	MessageT subject;
	MessageT message;

 public:
	EmailMessage(NickCore* nc, const MessageT& Subject, const MessageT& Message)
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
	Anope::string network;
	MessageT subject;
	MessageT message;

 public:
	EmailTemplate(const Anope::string& Name)
		: name(Name)
	{
	}

	EmailMessage MakeMessage(NickCore* nc) const
	{
		EmailMessage msg(nc, subject, message);
		msg.SetVariable("%N", network);
		return msg;
	}

	EmailMessage MakeMessage(NickAlias* na) const
	{
		EmailMessage msg(na->nc, subject, message);
		msg.SetVariable("%n", na->nick);
		msg.SetVariable("%N", network);
		return msg;
	}

	void DoReload(Configuration::Conf* conf)
	{
		Configuration::Block* mailblock = conf->GetBlock("mail");
		subject = mailblock->Get<const MessageT>(name + "_subject");
		message = mailblock->Get<const MessageT>(name + "_message");

		network = conf->GetBlock("networkinfo")->Get<const Anope::string>("networkname");
	}
};

#endif //ANOPE_MAIL_TEMPLATE_H
