/// Snoonet module specific typedefs

#ifndef ANOPE_SNOO_TYPES_H
#define ANOPE_SNOO_TYPES_H

typedef std::pair<Anope::string, time_t> ResetInfo;

typedef Serialize::Reference<NickCore> NickCoreRef;
typedef Serialize::Reference<NickAlias> NickAliasRef;

#endif //ANOPE_SNOO_TYPES_H
