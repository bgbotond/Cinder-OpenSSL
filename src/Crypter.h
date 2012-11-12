#ifndef __CRYPTER_H_INCLUDED__
#define __CRYPTER_H_INCLUDED__

#include <string>
#include <vector>
#include "openssl/pem.h"
#include "cinder/Filesystem.h"

namespace mndl { namespace crypter {

class Crypter
{
	typedef int(*CrypterFunction)(int,unsigned char *,unsigned char *, RSA *, int);

public:
	Crypter(){};
	~Crypter(){};

	static bool             generateKey( const ci::fs::path &privateKeyName, const ci::fs::path &publicKeyName, const std::string &password );

	static std::string      rsaPublicEncrypt  ( const ci::fs::path &publicKeyName                              , const std::string &text );
	static std::string      rsaPublicDencrypt ( const ci::fs::path &publicKeyName                              , const std::string &text );
	static std::string      rsaPrivateEncrypt ( const ci::fs::path &privateKeyName, const std::string &password, const std::string &text );
	static std::string      rsaPrivateDencrypt( const ci::fs::path &privateKeyName, const std::string &password, const std::string &text );

	static std::string      rsaPublicEncrypt  ( const std::string  &publicKey                                  , const std::string &text );
	static std::string      rsaPublicDencrypt ( const std::string  &publicKey                                  , const std::string &text );
	static std::string      rsaPrivateEncrypt ( const std::string  &privateKey,     const std::string &password, const std::string &text );
	static std::string      rsaPrivateDencrypt( const std::string  &privateKey,     const std::string &password, const std::string &text );

protected:
	static std::string      rsaEncrypt( RSA *key, const std::string &text, CrypterFunction crypterFunction );
	static std::string      rsaDecrypt( RSA *key, const std::string &text, CrypterFunction crypterFunction );

	static std::string base64Encode( const unsigned char *input, int length );
	static int         base64Decode( const std::string text, unsigned char *output );

	static void printUchar( const unsigned char *text, int length );
};

} } // namespace mndl::crypter

#endif // __CRYPTER_H_INCLUDED__
