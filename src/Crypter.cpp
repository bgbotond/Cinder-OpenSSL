#include <iostream>
#include <sstream>
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>
#include "Crypter.h"

using namespace std;
using namespace ci;

namespace mndl { namespace crypter {

const int   SUBSTRING_SIZE = 100;
const char *DELIMITER      = ":::";

bool Crypter::generateKey( const fs::path &privateKeyName, const fs::path &publicKeyName, const std::string &password )
{
	bool ret = true;

	OpenSSL_add_all_algorithms();

	RSA *rsa = RSA_generate_key( 1024, RSA_F4, NULL, NULL );
	const EVP_CIPHER *cipher = EVP_get_cipherbyname("des-ede3-cbc"); 

	BIO *bioPriv = BIO_new_file( privateKeyName.string().c_str(), "w" );
	if( bioPriv )
	{
		int check = PEM_write_bio_RSAPrivateKey( bioPriv, rsa, cipher, NULL, 0, NULL, (void*)password.c_str());

		if( check == 0 )
			ret = false;

		BIO_free( bioPriv );
	}

	BIO *bioPub = BIO_new_file( publicKeyName.string().c_str(), "w" );
	if( bioPub )
	{
		int check = PEM_write_bio_RSA_PUBKEY( bioPub, rsa );
//		int check = PEM_write_bio_RSAPublicKey( bioPub, rsa );

		if( check == 0 )
			ret = false;

		BIO_free( bioPub );
	}

	RSA_free(rsa);

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPublicEncrypt( const fs::path &publicKeyName, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bio = BIO_new_file( publicKeyName.string().c_str(), "r" );

	if( bio )
	{
		RSA *publicKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL );
//		RSA *publicKey = PEM_read_bio_RSAPublicKey( bio, NULL, NULL, NULL );

		ret = rsaEncrypt( publicKey, text, (CrypterFunction)RSA_public_encrypt );

		BIO_free( bio );
	}

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPublicDencrypt( const fs::path &publicKeyName, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bio = BIO_new_file( publicKeyName.string().c_str(), "r" );

	if( bio )
	{
		RSA *publicKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL );
//		RSA *publicKey = PEM_read_bio_RSAPublicKey( bio, NULL, NULL, NULL );

		ret = rsaDecrypt( publicKey, text, (CrypterFunction)RSA_public_decrypt );

		BIO_free( bio );
	}

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPrivateEncrypt( const fs::path &privateKeyName, const string &password, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bio = BIO_new_file( privateKeyName.string().c_str(), "r" );

	if( bio )
	{
		RSA *privateKey = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, (void*)password.c_str());

		ret = rsaEncrypt( privateKey, text, (CrypterFunction)RSA_private_encrypt );

		BIO_free( bio );
	}

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPrivateDencrypt( const fs::path &privateKeyName, const string &password, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bio = BIO_new_file( privateKeyName.string().c_str(), "r" );

	if( bio )
	{
		RSA *privateKey = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, (void*)password.c_str());

		ret = rsaDecrypt( privateKey, text, (CrypterFunction)RSA_private_decrypt );

		BIO_free( bio );
	}

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPublicEncrypt( const std::string &publicKeyData, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bpo       = BIO_new_mem_buf( (void*)publicKeyData.c_str(), publicKeyData.length());
	RSA *publicKey = PEM_read_bio_RSA_PUBKEY( bpo, NULL, NULL, NULL );

	ret = rsaEncrypt( publicKey, text, (CrypterFunction)RSA_public_encrypt );

	BIO_free( bpo       );
	RSA_free( publicKey );

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPublicDencrypt( const std::string &publicKeyData, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bpo       = BIO_new_mem_buf( (void*)publicKeyData.c_str(), publicKeyData.length());
	RSA *publicKey = PEM_read_bio_RSA_PUBKEY( bpo, NULL, NULL, NULL );

	ret = rsaDecrypt( publicKey, text, (CrypterFunction)RSA_public_decrypt );

	BIO_free( bpo       );
	RSA_free( publicKey );

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPrivateEncrypt( const std::string &privateKeyData, const string &password, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bpo        = BIO_new_mem_buf( (void*)privateKeyData.c_str(), privateKeyData.length());
	RSA *privateKey = PEM_read_bio_RSAPrivateKey( bpo, NULL, NULL, (void*)password.c_str());

	ret = rsaEncrypt( privateKey, text, (CrypterFunction)RSA_private_encrypt );

	BIO_free( bpo        );
	RSA_free( privateKey );

	EVP_cleanup();

	return ret;
}

string Crypter::rsaPrivateDencrypt( const std::string &privateKeyData, const string &password, const string &text )
{
	string ret;

	OpenSSL_add_all_algorithms();

	BIO *bpo        = BIO_new_mem_buf( (void*)privateKeyData.c_str(), privateKeyData.length());
	RSA *privateKey = PEM_read_bio_RSAPrivateKey( bpo, NULL, NULL, (void*)password.c_str());

	ret = rsaDecrypt( privateKey, text, (CrypterFunction)RSA_private_decrypt );

	BIO_free( bpo        );
	RSA_free( privateKey );

	EVP_cleanup();

	return ret;
}

string Crypter::rsaEncrypt( RSA *key, const string &text, CrypterFunction crypterFunction )
{
	string ret;

	if( key && crypterFunction )
	{
		int encryptSize = RSA_size( key );
		unsigned char *encryptText = (unsigned char*)OPENSSL_malloc( encryptSize );
		int posText = 0;
		int sizeText = text.size();

		while( posText < sizeText )
		{
			int subSize = min( SUBSTRING_SIZE, sizeText - posText );
			string subText = text.substr( posText, subSize );

			int size = crypterFunction( subSize, (unsigned char *)subText.c_str(), encryptText, key, RSA_PKCS1_PADDING );

			if( posText != 0 )
				ret += DELIMITER;

			ret += base64Encode( encryptText, size );

			if( size == -1 )
			{
				ret.clear();
				break;
			}

			posText += subSize;
		}

		OPENSSL_free( encryptText );
	}

	return ret;
}

string Crypter::rsaDecrypt( RSA *key, const string &text, CrypterFunction crypterFunction )
{
	string ret;

	if( key && crypterFunction )
	{
		int decryptSize = RSA_size( key );
		unsigned char *encryptText = (unsigned char*)OPENSSL_malloc( decryptSize );
		unsigned char *decryptText = (unsigned char*)OPENSSL_malloc( decryptSize + 1 ); // have space for 0 terminate

		boost::char_separator<char> sep( DELIMITER );
		boost::tokenizer< boost::char_separator<char> > tokens( text, sep );
		BOOST_FOREACH( const string& token, tokens )
		{
			int size = base64Decode( token, encryptText );
			int i = crypterFunction( size, encryptText, decryptText, key, RSA_PKCS1_PADDING );

			if( i == -1 )
			{
				ret.clear();
				break;
			}

			decryptText[ i ] = 0;

			ret += (char*)decryptText;
		}

		OPENSSL_free( encryptText );
		OPENSSL_free( decryptText );
	}

	return ret;
}

string Crypter::base64Encode( const unsigned char *input, int length )
{
	BIO *b64, *bmem;
	BUF_MEM *bptr;

	b64 = BIO_new( BIO_f_base64());
	bmem = BIO_new( BIO_s_mem());
//	BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );
	b64 = BIO_push( b64, bmem );
	BIO_write( b64, input, length );
	BIO_flush( b64 );
	BIO_get_mem_ptr( b64, &bptr );

	char *buffer = (char *)malloc( bptr->length );
	memcpy( buffer, bptr->data, bptr->length - 1 );
	buffer[ bptr->length - 1 ] = 0;

	BIO_free_all( b64 );

	string ret = buffer;
	free( buffer );

	return ret;
}

int Crypter::base64Decode( const string text, unsigned char *output )
{
	BIO *b64, *bmem;

	b64  = BIO_new( BIO_f_base64());
	bmem = BIO_new_mem_buf( (void*)text.c_str(), text.length());
	bmem = BIO_push( b64, bmem );

	int length = BIO_read( bmem, output, text.length());

	BIO_free_all( bmem );

	return length;
}

void Crypter::printUchar( const unsigned char *text, int length )
{
	cout << "======BEG===(" << length << ")===";
	for( int pos = 0; pos < length; ++pos )
	{
		if( pos != 0 )
			cout << "|";
			cout << (int)text[pos];
	}
	cout << "======END======" << endl;
}

} } // namespace mndl::crypter
