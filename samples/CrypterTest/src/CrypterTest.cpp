#include <iostream>
#include "Crypter.h"

using namespace mndl::crypter;
using namespace std;
using namespace ci;

void main()
{
	string text = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

	fs::path publicKey  = "public.pem";
	fs::path privateKey = "private.pem";
	string   password   = "secret";

//	Crypter::generateKey( privateKey, publicKey, password );

	{
		string encryptedText = Crypter::rsaPublicEncrypt( publicKey, text );
		string decryptedText = Crypter::rsaPrivateDencrypt( privateKey, password, encryptedText );

		if( text == decryptedText )
			cout << "public to private successful" << endl;
		else
			cout << "public to private unsuccessful" << endl;
	}

	{
		string encryptedText = Crypter::rsaPrivateEncrypt( privateKey, password, text );
		string decryptedText = Crypter::rsaPublicDencrypt( publicKey, encryptedText );

		if( text == decryptedText )
			cout << "private to public successful" << endl;
		else
			cout << "private to public unsuccessful" << endl;
	}
}