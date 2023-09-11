#pragma once
#include <Windows.h>
#include <string>

#include "StrEncrypt//Log.h"
#include "StrEncrypt//MetaString.h"

using namespace andrivet::ADVobfuscator;

//#include "StrEncrypt//MetaFSM.h"

/*
//-------------------------------------------------------------//
// "Malware related compile-time hacks with C++11" by LeFF   //
// You can use this code however you like, I just don't really //
// give a shit, but if you feel some respect for me, please //
// don't cut off this comment when copy-pasting... ;-)       //
//-------------------------------------------------------------//

////////////////////////////////////////////////////////////////////
template <int X> struct EnsureCompileTime {
	enum : int {
		Value = X
	};
};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
//Use Compile-Time as seed
#define Seed ((__TIME__[7] - '0') * 1  + (__TIME__[6] - '0') * 10  + \
              (__TIME__[4] - '0') * 60   + (__TIME__[3] - '0') * 600 + \
              (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
constexpr int LinearCongruentGenerator(int Rounds) {
	return 1013904223 + 1664525 * ((Rounds > 0) ? LinearCongruentGenerator(Rounds - 1) : Seed & 0xFFFFFFFF);
}
#define Random() EnsureCompileTime<LinearCongruentGenerator(10)>::Value //10 Rounds
#define RandomNumber(Min, Max) (Min + (Random() % (Max - Min + 1)))
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
template <int... Pack> struct IndexList {};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
template <typename IndexList, int Right> struct Append;
template <int... Left, int Right> struct Append<IndexList<Left...>, Right> {
	typedef IndexList<Left..., Right> Result;
};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
template <int N> struct ConstructIndexList {
	typedef typename Append<typename ConstructIndexList<N - 1>::Result, N - 1>::Result Result;
};
template <> struct ConstructIndexList<0> {
	typedef IndexList<> Result;
};
////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////
const char XORKEY = static_cast<char>(RandomNumber(0, 0xFF));
constexpr char EncryptCharacter(const char Character, int Index) {
	return Character ^ (XORKEY + Index);
}

template <typename IndexList> class CXorString;
template <int... Index> class CXorString<IndexList<Index...> > {
private:
	char Value[sizeof...(Index) + 1];
public:
	constexpr CXorString(const char* const String)
		: Value{ EncryptCharacter(String[Index], Index)... } {}

	char* decrypt() {
		for (int t = 0; t < sizeof...(Index); t++) {
			Value[t] = Value[t] ^ (XORKEY + t);
		}
		Value[sizeof...(Index)] = '\0';
		return Value;
	}

	char* get() {
		return Value;
	}
};

#define XorS(X, String) CXorString<ConstructIndexList<sizeof(String)-1>::Result> X(String)
#define XorString( String ) ( CXorString<ConstructIndexList<sizeof( String ) - 1>::Result>( String ).decrypt() )*/

struct IAString
{
private:
	DWORD EncKey;
	std::string EncValue;
	//std::string OutVal;
public:
	IAString(char * Value)
	{
		EncValue.clear();
		std::string sValue = Value;

		for (char c : sValue)
		{
			EncValue += c ^ EncKey;
		}
		sValue.clear();
	}
	IAString(const std::string & Value)
	{
		EncValue.clear();
		for (char c : Value)
		{
			EncValue += c ^ EncKey;
		}
	}
	IAString(const char * Value)
	{
		EncValue.clear();
		std::string sValue = Value;

		for (char c : sValue)
		{
			EncValue += c ^ EncKey;
		}
		sValue.clear();
	}
	IAString()
	{
		EncKey = rand() & 0xFF + 0x1;
		EncValue = "";
	}

	void operator += (const char * a1)
	{
		std::string buff = this->GetValue();
		buff += a1;
		this->SetValue((char*)buff.c_str());
		buff.clear();
	}
	void operator += (std::string a1)
	{
		std::string buff = this->GetValue();
		buff += a1;
		this->SetValue((char*)buff.c_str());
		buff.clear();
	}

	std::string GetValue()
	{
		std::string out;
		//OutVal = "";
		for (char c : EncValue)
		{
			out += c ^ EncKey;
		}
		return out;
	}
	void SetValue(char * Value)
	{
		EncValue.clear();
		std::string in = Value;
		for (char c : in)
		{
			EncValue += c ^ EncKey;
		}
		in.clear();
	}
};

#define XorString OBFUSCATED
