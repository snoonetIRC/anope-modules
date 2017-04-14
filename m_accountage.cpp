/*
 *
 * (C) 2003-2016 Anope Team
 * Contact us at team@anope.org
 *
 * Please read COPYING and README for further details.
 */

#include "module.h"

int userAge(User *u)
{
        time_t now=time(NULL);
        NickAlias *na=NickAlias::Find(u->nick);
        time_t creation=na->time_registered;
        time_t secondsSince=now-creation;
        return secondsSince/60/60/24;
};

class CommandGetAge : public Command
{
public:
        CommandGetAge(Module *creator) : Command(creator, "nickserv/age", 0, 0)
        {
                this->SetDesc(_("Displays age of a given nickname"));
                this->AllowUnregistered(false);
        }

        void Execute(CommandSource &source, const std::vector<Anope::string> &params) anope_override
        {
                source.Reply(_("Your account is %d days old."),userAge(source.GetUser()));
        }

        bool OnHelp(CommandSource &source, const Anope::string &subcommand) anope_override
        {
                this->SendSyntax(source);
                source.Reply(" ");
                source.Reply(_("Displays your account age."));
                                return true;
        }

};
class ModuleAccountAge : public Module
{

        CommandGetAge commandGetAge;
 public:
        ModuleAccountAge(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, EXTRA | VENDOR),
                commandGetAge(this)
        {

        }

        ~ModuleAccountAge()
        {
        }

        void OnUserLogin(User *u)
        {
                UplinkSocket::Message(u) << "SETAGE " << userAge(u);
        }

        void OnJoinChannel(User *u, Channel *c) {
                UplinkSocket::Message(u) << "SETAGE " << userAge(u);

        }



};

MODULE_INIT(ModuleAccountAge)
