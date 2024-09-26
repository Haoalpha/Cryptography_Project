#include "cryptopp/cryptlib.h"
#include "cryptopp/x509cert.h"
#include "cryptopp/secblock.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/pem.h"
#include "cryptopp/files.h"

#include <bits/stdc++.h>

using namespace std;
using namespace CryptoPP;

//extern const string pemCertificate;

int main(int argc, char* argv[])
{
string slash;
#ifdef _WIN32
	slash = '\\';
#elif __linux__
	slash = '/';
#endif

    string pdCertificate;
    string filename = "." + slash;
    cout << "Choose your type of certificate: " << endl;
    cout << "1. PEM" << endl;
    cout << "2. DER" << endl;
    cout << "Your choice: ";
    int optionValue;
    cin >> optionValue;

    X509Certificate cert;
    if (optionValue == 1)
    {
        filename += "cert.pem";
        FileSource fs(filename.c_str(), true, new StringSink(pdCertificate));
        StringSource ss(pdCertificate, true);
        PEM_Load(ss, cert);
    }
    else if (optionValue == 2)
    {
        filename += "cert.der";
        FileSource fs(filename.c_str(), true, new StringSink(pdCertificate));
        StringSource ss(pdCertificate, true);
        PEM_Load(ss, cert);
    }
    else
    {
        cout << "Your choice is not valid" << endl;
        exit(1);
    }

    const SecByteBlock& signature = cert.GetCertificateSignature();
    const SecByteBlock& toBeSigned = cert.GetToBeSigned();
    const X509PublicKey& publicKey = cert.GetSubjectPublicKey();
    
    //Check if the certificate is valid
    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);
    bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

    if (result)
        std::cout << "\nVerified certificate" << std::endl;
    else
    {
        std::cout << "\nFailed to verify certificate" << std::endl;
        exit(true);
    }

    //Give the information of the certificate
    cout << "\nThe information of the certificate is as follows:" << endl;
    cout << "\nVersion: " << cert.GetVersion() << endl;
    cout << "\nSerial Number: " << cert.GetSerialNumber() << endl;
    cout << "\nNot Before: " << cert.GetNotBefore() << endl;
    cout << "\nNot After: " << cert.GetNotAfter() << endl;
    cout << "\nSubject Identities:\n" << cert.GetSubjectIdentities() << endl;
    cout << "\nIssuer Identities: " << cert.GetIssuerDistinguishedName() << endl;
    cout << "\nSubject Key Identities: " << cert.GetSubjectKeyIdentifier() << endl;
    cout << "\nAuthority Key Identities: " << cert.GetAuthorityKeyIdentifier() << endl;
    cout << "\nSign Algorithm: " << cert.GetCertificateSignatureAlgorithm() << endl;
    cout << "\nSubject Public Key Algorithm: " << cert.GetSubjectPublicKeyAlgorithm() << endl;
    cout << "\nSignature: ";
    StringSource(signature, signature.size(), true, new HexEncoder(new FileSink(std::cout)));
    cout << endl;
    cout << "\nTo Be Signed: ";
    StringSource(toBeSigned, toBeSigned.size(), true, new HexEncoder(new FileSink(std::cout)));
    return 0;
}

