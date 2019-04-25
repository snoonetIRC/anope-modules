/// Snoonet module specific typedefs

#ifndef ANOPE_SNOO_TYPES_H
#define ANOPE_SNOO_TYPES_H

ExtensibleRef<Anope::string> passcodeExt("passcode");
ExtensibleRef<bool> unconfirmedExt("UNCONFIRMED");
ExtensibleRef<Anope::string> regserverExt("REGSERVER");

typedef Serialize::Reference<NickCore> NickCoreRef;
typedef Serialize::Reference<NickAlias> NickAliasRef;

typedef Reference<HTTPClient> HTTPClientRef;

#endif //ANOPE_SNOO_TYPES_H
