#include <iostream>
#include <sstream>
#include "Crypter.h"

using namespace std;
using namespace ci;

namespace mndl { namespace crypter {

const int SUBSTRING_SIZE = 100;

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

vector<int> Crypter::rsaPublicEncrypt( const fs::path &publicKeyName, const string &text )
{
	vector<int> ret;

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

string Crypter::rsaPublicDencrypt( const fs::path &publicKeyName, const vector<int> &text )
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

vector<int> Crypter::rsaPrivateEncrypt( const fs::path &privateKeyName, const string &password, const string &text )
{
	vector<int> ret;

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

string Crypter::rsaPrivateDencrypt( const fs::path &privateKeyName, const string &password, const vector<int> &text )
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

vector<int> Crypter::rsaEncrypt( RSA *key, const string &text, CrypterFunction crypterFunction )
{
	vector<int> ret;

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

			addData( ret, encryptText, size );

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

string Crypter::rsaDecrypt( RSA *key, const vector<int> &text, CrypterFunction crypterFunction )
{
	string ret;

	if( key && crypterFunction )
	{
		int decryptSize = RSA_size( key );
		unsigned char *encryptText = (unsigned char*)OPENSSL_malloc( decryptSize );
		unsigned char *decryptText = (unsigned char*)OPENSSL_malloc( decryptSize + 1 ); // have space for 0 terminate

		int from = 0;
		while( from < (int)text.size())
		{
			int size = getData( text, encryptText, from );
			from += size + 1;

			int i = crypterFunction( size, encryptText, decryptText, key, RSA_PKCS1_PADDING );

			if( i == -1 )
			{
				ret.clear();
				break;
			}

			decryptText[i] = 0;
			ret += (char*)decryptText;
		}

		OPENSSL_free( encryptText );
		OPENSSL_free( decryptText );
	}

	return ret;
}

void Crypter::addData( vector<int> &vec, const unsigned char *data, int size )
{
	vec.push_back( size );
	for( int pos = 0; pos < size; ++pos )
	{
		vec.push_back( data[pos] );
	}
}

int Crypter::getData( const vector<int> &vec, unsigned char *data, int from )
{
	int size = vec[from];
	from++;

	for( int pos = from; pos < from + size; ++pos )
	{
		data[pos-from] = vec[pos];
	}

	return size;
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

string Crypter::toString( const vector<int> &text )
{
	stringstream strStream;
	int size = text.size();

	for( int pos = 0; pos < size; ++pos )
	{
		strStream << text[pos] << "|";
	}

	return strStream.str();
}

vector<int> Crypter::fromString( const string &text )
{
	vector<int> ret;
	int size = text.size();

	int i = 0;
	for( int pos = 0; pos < size; ++pos )
	{
		if( text[pos] == '|' )
		{
			ret.push_back( i );
			i = 0;
			continue;
		}

		i *= 10;
		i += text[pos] - '0';
	}

	return ret;
}

} } // namespace mndl::crypter
