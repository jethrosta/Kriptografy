#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handleErrors(const char* message)
{
    std::cerr << "Error: " << message << std::endl;
    exit(1);
}

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file> <key_file>" << std::endl;
        return 1;
    }

    const char* inputFilename = argv[1];
    const char* outputFilename = argv[2];
    const char* keyFilename = argv[3];

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate AES key
    unsigned char aesKey[32]; // 256-bit key
    if (RAND_bytes(aesKey, sizeof(aesKey)) != 1)
    {
        handleErrors("Failed to generate AES key using OpenSSL.");
    }

    // Open the key file for writing
    std::ofstream keyFile(keyFilename, std::ios::binary);
    if (!keyFile)
    {
        handleErrors("Failed to open key file for writing.");
    }

    // Write the AES key to the key file
    keyFile.write(reinterpret_cast<const char*>(aesKey), sizeof(aesKey));
    keyFile.close();

    // Open the input file for reading
    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile)
    {
        handleErrors("Failed to open input file.");
    }

    // Open the output file for writing
    std::ofstream outputFile(outputFilename, std::ios::binary);
    if (!outputFile)
    {
        handleErrors("Failed to open output file.");
    }

    // Create an AES encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handleErrors("Failed to create encryption context.");
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesKey) != 1)
    {
        handleErrors("Failed to initialize encryption operation.");
    }

    // Buffer for reading input file data
    const size_t bufferSize = 4096;
    unsigned char buffer[bufferSize];

    // Encrypt and write data to the output file
    int bytesRead;
    while ((bytesRead = inputFile.read(reinterpret_cast<char*>(buffer), bufferSize).gcount()) > 0)
    {
        int cipherLength;
        if (EVP_EncryptUpdate(ctx, buffer, &cipherLength, buffer, bytesRead) != 1)
        {
            handleErrors("Encryption error.");
        }
        outputFile.write(reinterpret_cast<const char*>(buffer), cipherLength);
    }

    // Finalize encryption
    int finalCipherLength;
    if (EVP_EncryptFinal_ex(ctx, buffer, &finalCipherLength) != 1)
    {
        handleErrors("Finalization error.");
    }
    outputFile.write(reinterpret_cast<const char*>(buffer), finalCipherLength);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
