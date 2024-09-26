
#include <iostream>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;

#include <cstring>
using std::strcpy;

#include <string>
using std::string;

#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include<numeric>
#include<vector>
#include <chrono>
using namespace std::chrono;
#include<time.h>
#include "cryptopp/stdafx.h"
#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#ifndef DLL_EXPORT 
#ifdef _WIN32 
#define DLL_EXPORT __declspec(dllexport) 
#else 
#define DLL_EXPORT 
#endif 
#endif

extern "C"{
    DLL_EXPORT bool GenerateKey(const char* chrPriKey, const char* chrPubKey, const char* chrFormat);
    DLL_EXPORT bool ECCbasedSign(const char* chrFormat, const char* chrPriKey, const char* chrFileName, const char* chrSignature);
    DLL_EXPORT bool ECCbasedVerify(const char* chrFormat, const char* chrPubKey, const char* chrFileName, const char* chrSignature);
}

void SaveDER(const string& filename, const BufferedTransformation& bt) {
    FileSink keyfile(filename.c_str());
	bt.CopyTo(keyfile);
	keyfile.MessageEnd();
}

void SavePEM(const string& filename, const BufferedTransformation& bt) {
    Base64Encoder encoder(new FileSink(filename.c_str()), true);
    bt.CopyTo(encoder);
    encoder.MessageEnd();
}

void LoadDER(const string& filename, BufferedTransformation& bt) {
    FileSource keyfile(filename.c_str(), true);
	keyfile.TransferTo(bt);
	bt.MessageEnd();
}

void LoadPEM(const string& filename, BufferedTransformation& bt) {
    FileSource keyfile(filename.c_str(), true, new Base64Decoder);
	keyfile.TransferTo(bt);
	bt.MessageEnd();
}

bool GenerateKey(const char* chrPriKey, const char* chrPubKey, const char* chrFormat) {
    string prikey(chrPriKey), pubkey(chrPubKey), format(chrFormat);
    
    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    DL_GroupParameters_EC<ECP> params(CryptoPP::ASN1::secp256k1());
    privateKey.Initialize(prng, params);

    ECDSA<ECP, SHA256>::PublicKey publicKey;
    privateKey.MakePublicKey(publicKey);

    ByteQueue private_queue, public_queue;
    privateKey.Save(private_queue);
    publicKey.Save(public_queue);

    if (format == "DER") {
        SaveDER(prikey, private_queue);
        SaveDER(pubkey, public_queue);
    }
    else if (format == "PEM") {
        SavePEM(prikey, private_queue);
        SavePEM(pubkey, public_queue);
    }
    else {
        cout << "Unsupported format" << endl;
        return false;
    }
    
    return true;
}

bool ECCbasedSign(const char* chrFormat, const char* chrPriKey, const char* chrFileName, const char* chrSignature) {
    string format(chrFormat), prikey(chrPriKey), filename(chrFileName), message, signature;

    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::PrivateKey key;
    ByteQueue private_queue;

    if (format == "DER") {
        LoadDER(prikey, private_queue);
    }
    else if (format == "PEM") {
        LoadPEM(prikey, private_queue);
    }
    else {
        cout << "Unsupported format" << endl;
        return false;
    }
    
    key.Load(private_queue);

    message.clear();
    FileSource (filename.c_str(), true,
        new StringSink(message)
    );

    signature.clear();
    StringSource(message, true,
        new SignerFilter( prng,
            ECDSA<ECP, SHA256>::Signer(key),
            new StringSink(signature)
        )
    );

    StringSource(signature, true,
        new HexEncoder(
            new FileSink(chrSignature)
        )
    );

    return !signature.empty();
}

bool ECCbasedVerify(const char* chrFormat, const char* chrPubKey, const char* chrFileName, const char* chrSignature) {
    string format(chrFormat), pubkey(chrPubKey), filename(chrFileName), f_signature(chrSignature), message, signature;

    ECDSA<ECP, SHA256>::PublicKey key;
    ByteQueue public_queue;
    bool result = false;

    if (format == "DER") {
        LoadDER(pubkey, public_queue);
    }
    else if (format == "PEM") {
        LoadPEM(pubkey, public_queue);
    }
    else {
        cout << "Unsupported format" << endl;
        return false;
    }
    
    key.Load(public_queue);

    message.clear();
    FileSource (filename.c_str(), true,
        new StringSink(message)
    );

    signature.clear();
    FileSource (f_signature.c_str(), true,
        new HexDecoder(
            new StringSink(signature)
        )
    );

    StringSource(signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP, SHA256>::Verifier(key),
            new ArraySink(
                (CryptoPP::byte*)&result, sizeof(result)
            )
        )
    );

    // StringSource(signature+message, true,
    //     new SignatureVerificationFilter(
    //         ECDSA<ECP, SHA256>::Verifier(key),
    //         new ArraySink((CryptoPP::byte*) &result, sizeof(result)),
    //             SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END
    //     )
    // );

    return result;
}
float calculateAverage(const std::vector<float>& vec) {
    if (vec.empty()) {
        throw std::invalid_argument("The vector is empty.");
    }

    double sum = std::accumulate(vec.begin(), vec.end(), 0.0);
    return sum / vec.size();
}
void test(){
    std::string filePath1, filePath2, filePath3, filePath4, filePath5, filePath6;
    filePath1 = "files/input1.txt";
    filePath2 = "files/input2.txt";
    filePath3 = "files/input3.txt";
    filePath4 = "files/input4.txt";
    filePath5 = "files/input5.txt";
    filePath6 = "files/input6.txt";

    string paths[6] = {filePath1, filePath2, filePath3, filePath4, filePath5, filePath6};
    std::string format = "PEM";
    std::string privatekey = "private.pem";
    std::string publickey = "public.pem";
    std::string output = "signed.bin";

    for (int i = 0; i < 6; i++){
        std::cout << "Running File Path: " << paths[i] << std::endl;
        std::vector<float> sign, verify;
        for (int j = 0; j < 1000; j++){
            GenerateKey(privatekey.c_str(), publickey.c_str(), format.c_str());
            auto sign_start = high_resolution_clock::now();
            ECCbasedSign(format.c_str(), privatekey.c_str(), paths[i].c_str(),output.c_str());
            auto sign_end = high_resolution_clock::now();  // End timing
            auto sign_duration = duration_cast<milliseconds>(sign_end - sign_start);
            sign.push_back(sign_duration.count());
            auto verify_start = high_resolution_clock::now();
            ECCbasedVerify(format.c_str(), publickey.c_str(), paths[i].c_str(),output.c_str());
            auto verify_end = high_resolution_clock::now();  // End timing
            auto verify_duration = duration_cast<milliseconds>(verify_end - verify_start);
            verify.push_back(verify_duration.count());
        }
        float signAverage = calculateAverage(sign);
        float verifyAverage = calculateAverage(verify);
        std::cout << "Finished File Path: " << paths[i] << std::endl;
        std::cout << "Sign average: " << signAverage << std::endl; 
        std::cout << "Verify average: " << verifyAverage << std::endl;

    }
}
int main(int argc, char* argv[]) {
#ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
#endif

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    //test();
    if (argc < 5) {
        cerr << "Usage:\n"
             << argv[0] << " genkey <private key file> <public key file> <format>\n"
             << argv[0] << " signing <format> <private key file> <file name> <signature file>\n"
             << argv[0] << " verify <format> <public key file> <file name> <signature file>\n"
             << "<format>: [DER|PEM]\n";
        return -1;
    }

    string choice = argv[1];

    if (choice == "genkey") {
        if(GenerateKey(argv[2], argv[3], argv[4])) {
            cout << "Generate key successfully" << endl;
        }
        else {
            cout << "Generate key failed" << endl;
        }
    }
    else if (choice == "signing") {
        if(ECCbasedSign(argv[2], argv[3], argv[4], argv[5])) {
            cout << "Sign successfully" << endl;
        }
        else {
            cout << "Sign failed" << endl;
        }
    }
    else if (choice == "verify") {
        if(ECCbasedVerify(argv[2], argv[3], argv[4], argv[5])) {
            cout << "Verify successfully" << endl;
        }
        else {
            cout << "Verify failed" << endl;
        }
    }
    else {
        cout << "Choice doesn't exists" << endl;
    }

    return 0;
}