#ifndef ANOPE_JSON_API_H
#define ANOPE_JSON_API_H

#include "modules/httpd.h"
#include "modules/sql.h"

class JsonValue;

class JsonString;

class JsonObject;

class JsonArray;

typedef long JsonNumber;

static const char hexchars[] = "0123456789abcdef";

class JsonString
	: public std::string
{
 public:
	static std::ostream& EscapeJSON(const std::string& str, std::ostream& out)
	{
		for (std::string::const_iterator it = str.begin(); it != str.end(); ++it)
		{
			unsigned char c = (unsigned char) *it;
			switch (c)
			{
				case '"':
				case '\\':
					out << '\\' << c;
					continue;
				case '\b':
					out << "\\b";
					break;
				case '\f':
					out << "\\f";
					break;
				case '\n':
					out << "\\n";
					break;
				case '\r':
					out << "\\r";
					break;
				case '\t':
					out << "\\t";
					break;
				default:
					if (' ' <= c && c <= '~')
					{
						out << c;
					}
					else
					{
						out << "\\u"
							<< hexchars[(c >> 12) & 0x0F]
							<< hexchars[(c >> 8) & 0x0F]
							<< hexchars[(c >> 4) & 0x0F]
							<< hexchars[c & 0x0F];
					}
					break;
			}
		}
		return out;
	}

 public:
	JsonString()
	{
	}

	JsonString(const char* str)
		: std::string(str)
	{
	}

	JsonString(const Anope::string& str)
		: std::string(str.c_str())
	{
	}

	JsonString(const std::string& str)
		: std::string(str)
	{
	}

	JsonString(const JsonString& str)
		: std::string(str)
	{
	}

	std::string str() const
	{
		std::stringstream out;
		str(out);
		return out.str();
	}

	std::ostream& str(std::ostream& sstr) const
	{
		sstr << '"';
		EscapeJSON(*this, sstr);
		return sstr << '"';
	}
};

class JsonValue
{
 public:
	enum ValueType
	{
		JSON_STRING,
		JSON_OBJECT,
		JSON_ARRAY,
		JSON_NUMBER,
		JSON_NULL,
		JSON_TRUE,
		JSON_FALSE
	};

	ValueType type;

	union
	{
		JsonObject* object;
		JsonArray* array;
		JsonString* string;
		JsonNumber* number;
	};

	void Reset();

	JsonValue& SetType(ValueType newType);

	JsonValue()
		: type(JSON_NULL)
		, object(NULL)
	{
	}

	JsonValue(const JsonValue& other)
		: type(JSON_NULL)
		, object(NULL)
	{
		*this = other;
	}

	template<typename T>
	JsonValue(const T& value)
		: type(JSON_NULL)
		, object(NULL)
	{
		*this = value;
	}

	JsonValue& operator=(const JsonValue& other)
	{
		this->SetType(other.type);
		switch (other.type)
		{
			case JSON_NULL:
			case JSON_TRUE:
			case JSON_FALSE:
				object = other.object;
				break;
			case JSON_OBJECT:
				*this = *other.object;
				break;
			case JSON_STRING:
				*this = *other.string;
				break;
			case JSON_ARRAY:
				*this = *other.array;
				break;
			case JSON_NUMBER:
				*number = *other.number;
				break;
		}
		return *this;
	}

	JsonValue& operator=(const char* str)
	{
		this->SetType(JSON_STRING);
		string->assign(str);
		return *this;
	}

	JsonValue& operator=(const Anope::string& str)
	{
		this->SetType(JSON_STRING);
		string->assign(str.str());
		return *this;
	}

	JsonValue& operator=(const std::string& str)
	{
		this->SetType(JSON_STRING);
		string->assign(str);
		return *this;
	}

	JsonValue& operator=(bool b)
	{
		this->SetType(b ? JSON_TRUE : JSON_FALSE);
		return *this;
	}

	JsonValue& operator=(const JsonObject& obj);

	JsonValue& operator=(const JsonArray& obj);

	JsonValue& operator=(const JsonNumber& obj)
	{
		this->SetType(JSON_NUMBER);
		*number = obj;
		return *this;
	}

	void SetNull()
	{
		this->SetType(JSON_NULL);
	}

	virtual ~JsonValue()
	{
		this->Reset();
	}

	bool GetBool(bool& b) const
	{
		switch (type)
		{
			case JSON_TRUE:
			case JSON_FALSE:
				b = type == JSON_TRUE;
				return true;
				break;
			default:
				return false;
		}
	}

	std::string str() const
	{
		std::stringstream sstr;
		str(sstr);
		return sstr.str();
	}

	std::ostream& str(std::ostream& os) const;
};

class JsonObject
	: public std::map<JsonString, JsonValue>
{
	typedef std::map<JsonString, JsonValue> BaseT;
 public:
	std::ostream& str(std::ostream& os) const
	{
		if (empty())
			return os << "{}";

		char sep = '{';
		for (JsonObject::const_iterator it = begin(); it != end(); ++it)
		{
			os << sep;
			it->first.str(os) << ':';
			it->second.str(os);
			sep = ',';
		}
		return os << "}";
	}

	std::string str() const
	{
		std::stringstream sstr;
		str(sstr);
		return sstr.str();
	}

	JsonObject()
	{
	}

	JsonObject(const JsonObject& other)
		: BaseT(other)
	{
	}

	JsonObject(const BaseT& other)
		: BaseT(other)
	{
	}
};

class JsonArray
	: public std::vector<JsonValue>
{
	typedef std::vector<JsonValue> BaseT;
 public:
	std::ostream& str(std::ostream& os) const
	{
		if (empty())
			return os << "[]";

		char sep = '[';
		for (JsonArray::const_iterator it = begin(); it != end(); ++it)
		{
			os << sep;
			it->str(os);
			sep = ',';
		}
		return os << "]";
	}

	std::string str() const
	{
		std::stringstream sstr;
		str(sstr);
		return sstr.str();
	}

	JsonArray()
	{
	}

	JsonArray(const JsonArray& other)
		: BaseT(other)
	{
	}

	JsonArray(const BaseT& other)
		: BaseT(other)
	{
	}
};

class JsonSerializeData
	: public SQL::Data
{
 public:
	void GetJson(JsonObject& object) const
	{
		for (Map::const_iterator it = data.begin(); it != data.end(); ++it)
		{
			std::stringstream* sstr = it->second;
			std::string name = it->first.str();
			if (sstr)
			{
				if (GetType(it->first) == DT_INT)
				{
					JsonNumber val;
					*sstr >> val;
					object[name] = val;
				}
				else
				{
					object[name] = sstr->str();
				}
			}
		}
	}
};

class JsonAPIEndpoint
	: public HTTPPage
{
 public:
	JsonAPIEndpoint(const Anope::string& u)
		: HTTPPage("/api/" + u, "application/json")
	{
	}
};

JsonValue& JsonValue::SetType(JsonValue::ValueType newType)
{
	if (type != newType)
	{
		this->Reset();
		type = newType;

		switch (type)
		{
			case JSON_STRING:
				string = new JsonString;
				break;
			case JSON_OBJECT:
				object = new JsonObject;
				break;
			case JSON_ARRAY:
				array = new JsonArray;
				break;
			case JSON_NUMBER:
				number = new JsonNumber;
				break;
			case JSON_NULL:
			case JSON_TRUE:
			case JSON_FALSE:
				break;
		}
	}
	return *this;
}

std::ostream& JsonValue::str(std::ostream& os) const
{
	switch (type)
	{
		case JSON_TRUE:
			os << "true";
			break;
		case JSON_FALSE:
			os << "false";
			break;
		case JSON_NULL:
			os << "null";
			break;
		case JSON_STRING:
			string->str(os);
			break;
		case JSON_NUMBER:
			os << *number;
			break;
		case JSON_OBJECT:
			object->str(os);
			break;
		case JSON_ARRAY:
			array->str(os);
			break;
	}
	return os;
}

void JsonValue::Reset()
{
	switch (type)
	{
		case JSON_ARRAY:
			delete array;
			break;
		case JSON_OBJECT:
			delete object;
			break;
		case JSON_STRING:
			delete string;
			break;
		case JSON_NUMBER:
			delete number;
			break;
		case JSON_TRUE:
		case JSON_FALSE:
		case JSON_NULL:
			break;
	}

	type = JSON_NULL;
	object = NULL;
}

JsonValue& JsonValue::operator=(const JsonObject& obj)
{
	this->SetType(JSON_OBJECT);
	object->clear();
	object->insert(obj.begin(), obj.end());
	return *this;
}

JsonValue& JsonValue::operator=(const JsonArray& obj)
{
	this->SetType(JSON_ARRAY);
	array->assign(obj.begin(), obj.end());
	return *this;
}

#endif //ANOPE_JSON_API_H
