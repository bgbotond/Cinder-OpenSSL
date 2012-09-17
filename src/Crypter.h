#ifndef __CRYPTER_H_INCLUDED__
#define __CRYPTER_H_INCLUDED__

#include <string>
#include <vector>
#include "openssl/pem.h"
#include "cinder/Filesystem.h"

namespace mndl { namespace crypter {

/*
	content of std::vector<int> cryptedText:

	{ number of elements in block1, ...block1 encrypted data...
	, number of elements in block2, ...block2 encrypted data...
	  ...
	, number of elements in blockN, ...blockN encrypted data... }
*/

class Crypter
{
	typedef int(*CrypterFunction)(int,unsigned char *,unsigned char *, RSA *, int);

public:
	Crypter(){};
	~Crypter(){};

	static bool             generateKey( const ci::fs::path &privateKeyName, const ci::fs::path &publicKeyName, const std::string &password );

	static std::vector<int> rsaPublicEncrypt  ( const ci::fs::path &publicKeyName                              , const std::string      &text );
	static std::string      rsaPublicDencrypt ( const ci::fs::path &publicKeyName                              , const std::vector<int> &text );
	static std::vector<int> rsaPrivateEncrypt ( const ci::fs::path &privateKeyName, const std::string &password, const std::string      &text );
	static std::string      rsaPrivateDencrypt( const ci::fs::path &privateKeyName, const std::string &password, const std::vector<int> &text );

	static std::string      toString  ( const std::vector<int> &text );
	static std::vector<int> fromString( const std::string      &text );

protected:
	static std::vector<int> rsaEncrypt( RSA *key, const std::string      &text, CrypterFunction crypterFunction );
	static std::string      rsaDecrypt( RSA *key, const std::vector<int> &text, CrypterFunction crypterFunction );

	static void addData(       std::vector<int> &vec, const unsigned char *data, int size );
	static int  getData( const std::vector<int> &vec,       unsigned char *data, int from );

	static void printUchar( const unsigned char *text, int length );
};

} } // namespace mndl::crypter

#endif // __CRYPTER_H_INCLUDED__
