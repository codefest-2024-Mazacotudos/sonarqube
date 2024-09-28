#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <random>
#include <cstdint>
#include <climits>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;
using namespace std;

CryptoPP::AutoSeededRandomPool rng;

const string RSA_PRIVATE_KEY =
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLoM2BKUYKbSAN"
"2lBAVENhl5tL/NTjZ/CisUJG8nbqQn3F7ZEm/UHFd+9dFxZBvejZs/uiFdjSdf1r"
"dnO6UjLPU4qV30u9vrcg2jiZNvMBfJG0e8ryTfD8wnw4MC1G/ePPp1oGp4tJCU13"
"y/FJwFKrUpZcllIOShGiIG3+p695ZglTeNfBPv0LRlNuPNeJ6i9xuXDQkeUffMnp"
"O1fmghr3G+Y8/YLj3Oi4ycrwIJ25szw7ITN7tZR5ZZSZNNrRsb//0Xf6TbExiCxz"
"elr2ViDaYBX70BQmZTemqdflMVncQmcBfd4U7g7oOn8PaWeXn0DPjQBtqsm7JrvQ"
"VHopI7QRAgMBAAECggEAE0D1ZX7WU1KNqxmnKGn/RAlOgxEZPRZdI7kAhA5VjaFz"
"XIVxyd68+xOz05jE/zrae0lAJAuOSJok9+YHm8i9aqqiyjiGpB6WGLphiyUttYiG"
"i2sAHcieXnvyPGrbwSBtC7uucL4jVqjVRRxIyJkxh+cDdiY1hIne4HZSCDfpSOBg"
"lUbAhq9I8VUXF1JprM1TlaIGSIMJwrE/JbAA4BHopF+DA92g1KMyS1/tcTmhRB1D"
"9+vndL5hoXshWI7xzHNmK9tF0TPJYK9IPoOtGb3N8xs5p68CrfWx5+pZSZOor+HI"
"InB/nld4oAEEz2ZDBJBGWN95POSpvnfGbHSO14De1QKBgQDp8GGxCUJDmBN5tBaA"
"UaxKS6IipPX3U7CCRY54J1LiDuzyv+YoB0no7eSL1UP/oZulO+sSuXGrqwx+qe5A"
"in2hUR4rvQaFWvAtGh+4YW9OdjTvfQbHcYOQpK2YaZdVmx/mQnABjpCDa6yHfnFI"
"ZKsvwPM4PKIXdL/DG11hJmfX/QKBgQDe1KyYXDhvhHHtPYgy1etRMQ4La0SViKpr"
"xPdt4K0+/SSTfBK67pXKYjECiQcLmiFwdz0C75IRB2jiY+MznKOQb0nvTHyizr+J"
"NIcXpH2SWd/pFBS7CrEN6/H5PCDD8LjoqE5woolWQdA1Si2dLULKUILUIDld1pcv"
"4+LVDMjWpQKBgBp8eNMOdU4p3aqd1R5aIOOYhJbfjmmeNBHLxkGcUin9/p3NVEWb"
"7aZNqN6cGsLKjVC74/WOwWvqRdPhcXQlOewVvxC8qgxXK3Ivzv+VKID9qSikQyw5"
"kefCfVUQP24VzhrH0t6aQYpfmn0Mt862dxtFAUSQuNlnAn8Yjg39xywRAoGBAL/6"
"fSTbNygk9L6Pp9scYJvX5qDB7xnh3+nvjbkVvE0rbaq/V6fDzDvMMytbAT3mse6i"
"XGc+HhsbxipeIq4hwu26Y/mObUcbVvuPzN/6sNE5K2c1DNNE19wFrrirLBOEPtr7"
"vnDeJ/KvywFOglQLXaLOkJjPln0ZV7JD5PbnB9WdAoGBAM0LTx3ggk0VRMcBygdA"
"5mge79d/thsdPoVya2TrflwaQ4PoY2qcBxjQnXA0ve0Vch7gQTQpTW5VsntQB5+a"
"GU0F1zhHS4IGmU8bKVjykw8WTT6rZD/iLFTuBK1oYtgNjwqZF/lWFSDS3ZvfTANV"
"yCzt+8fFmBp4Xh/9p5zIYXio";

const string RSA_PUBLIC_KEY = 
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6DNgSlGCm0gDdpQQFRD"
"YZebS/zU42fworFCRvJ26kJ9xe2RJv1BxXfvXRcWQb3o2bP7ohXY0nX9a3ZzulIy"
"z1OKld9Lvb63INo4mTbzAXyRtHvK8k3w/MJ8ODAtRv3jz6daBqeLSQlNd8vxScBS"
"q1KWXJZSDkoRoiBt/qeveWYJU3jXwT79C0ZTbjzXieovcblw0JHlH3zJ6TtX5oIa"
"9xvmPP2C49zouMnK8CCdubM8OyEze7WUeWWUmTTa0bG//9F3+k2xMYgsc3pa9lYg"
"2mAV+9AUJmU3pqnX5TFZ3EJnAX3eFO4O6Dp/D2lnl59Az40AbarJuya70FR6KSO0"
"EQIDAQAB";

// Se declara el tamaño de los batches
const size_t BATCH_SIZE = 1000 * 1024 * 1024;
void encrypt(const string& input_path, const string& output_path);
void decrypt(const string& input_path, const string& output_path);

int main(int argc, char* argv[]) {

    if (argc != 4) {
        cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>" << endl;
        return 1;
    }

    string operation = argv[1];
    string input_path = argv[2];
    string output_path = argv[3];

    if (operation == "encrypt") {
        encrypt(input_path, output_path);
    }
    else if (operation == "decrypt") {
        decrypt(input_path, output_path);
    }
    else {
        cerr << "Operacion no valida: " << operation << endl;
        return 1;
    }
    return 0;
}

// Función que genera una semilla aleatoria que sirve para generar las llaves y los vectores de inicialización 
uint16_t generateRandomSeed() {
    // Se inicializa un generador de números aleatorios que toma como semilla el tiempo actual 
    srand(static_cast<unsigned int>(std::time(0)));
    // Se obtiene un número aleatorio de 16 bits
    return static_cast<uint16_t>(rand() % 65536);
}

// Función para generar una secuencia LFSR de longitud dada
// uint16_t se utiliza para trabajar con el campo finito GF(2^16). Cada operación en el LFSR se realiza dentro de los límites de 16 bits
vector<uint16_t> generateLFSRSequence(uint16_t start_state, int length) {
    vector<uint16_t> sequence(length);  // Vector para almacenar la secuencia
    uint16_t lfsr = start_state;        // Estado inicial del LFSR
    uint16_t period = 0;

    for (int i = 0; i < length; ++i) {
        // Almacenar el estado actual del LFSR en la secuencia
        sequence[i] = lfsr;

        // Obtener el bit menos significativo (LSB)
        unsigned lsb = lfsr & 1u;
        // Desplazar el registro hacia la derecha
        lfsr >>= 1;
        // Aplicar la máscara de retroalimentación si el LSB es 1
        if (lsb) {
            // ^= es un XOR. 0xB400u es: 1011 0100 0000 0000 el cual es un polinomio primitivo. Es decir garantiza un período máximo de 2^16 -1 estados
            lfsr ^= 0xB400u;
        }
        ++period;
    }

    return sequence;
}

// Función para generar las llaves de 32 Bytes cifrado de forma dinámica a partir de una semilla.
string generateDynamicKey(uint16_t seed) {
    mt19937 generador(seed); // Inicializar el generador de números aleatorios con la semilla
    normal_distribution<double> distribucion(0.0, 1.0); // Distribución normal estándar (media 0, desviación estándar 1)
    double numero_normal = distribucion(generador); // Generar un número aleatorio de la distribución normal
    // Se genera un número de 16 bits a partir del número aleatorio de esta distribución normal
    uint16_t adjusted_seed = static_cast<uint16_t>((numero_normal + 3) * (UINT16_MAX / 6.0));

    // Asegurar que el número esté en el rango de 16 bits sin signo
    if (adjusted_seed > UINT16_MAX) {
        adjusted_seed = UINT16_MAX;
    }
    int length = 64;

    // A partir de la semilla se genera una secuencia LFSR
    vector<uint16_t> seedKey = generateLFSRSequence(adjusted_seed, length);

    // Se almacena esta secuencia como un string
    string string_key;
    for (const auto& elem : seedKey) {
        string_key.append(reinterpret_cast<const char*>(&elem), sizeof(uint16_t));
    }

    // Para aumentar la seguridad y entropía de la llave se obtiene el hash de esta llave
    SHA256 hash;
    string key;

    // Se calcula el hash SHA256 de la secuencia el cual funcionará como la llave
    StringSource ss(string_key, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(key), false)));
    
    // Se retorna la llave
    return key;
}

// Función para generar los vectores de inicialización de 16 Bytes de forma dinámica a partir de una semilla.
string generateDynamicIV(uint16_t seed) {
    int length = 64;

    // A partir de la semilla se genera una secuencia LFSR
    vector<uint16_t> seedIV = generateLFSRSequence(seed, length);

    // Se almacena esta secuencia como string
    string iv;
    for (const auto& elem : seedIV) {
        iv.append(reinterpret_cast<const char*>(&elem), sizeof(uint16_t));
    }

    // Se retorna esta secuencia como vector de inicialización
    return iv;
}

// Función que se encarga de encriptar una imagen utilizando AES y el cifrado por bloques CTR
void encrypt(const string& input_path, const string& output_path) {

    // Se genera una semilla
    uint16_t seed = generateRandomSeed();

    // A partir de esta semilla se genera la llave y el vector de inicialización para cifrar
    string key = generateDynamicKey(seed);
    string iv = generateDynamicIV(seed);

    // Se obtienen las rutas de la imagen a leer y la imagen a almacenar
    cout << "input_path=" << input_path << endl;
    cout << "output_path=" << output_path << endl;

    auto processBatch = [](ifstream& inImage, ofstream& outImage, SHA256& sha, CTR_Mode<AES>::Encryption& enc) {
        // Se declara el tamaño del buffer para leer las imágenes en batches
        vector<CryptoPP::byte> buffer(BATCH_SIZE);
        while (inImage) {
            // Se lee un batch
            inImage.read(reinterpret_cast<char*>(buffer.data()), BATCH_SIZE);
            streamsize bytesProcesados = inImage.gcount();
            if (bytesProcesados > 0) {
                // Se calcula el hash
                sha.Update(buffer.data(), bytesProcesados);
                vector<CryptoPP::byte> encrypted(bytesProcesados);
                // Se cifra el batch con la llave y el vector de inicialización generados
                enc.ProcessData(encrypted.data(), buffer.data(), bytesProcesados);
                // Se guarda el batch cifrado en la imagen de salida
                outImage.write(reinterpret_cast<char*>(encrypted.data()), bytesProcesados);
            }
        }
    };

    try {
        // Se declara el método de cifrado como AES con el cifrado por bloques CTR
        CTR_Mode<AES>::Encryption enc;
        // Se le asigna al encriptador la llave y el vector de inicialización
        enc.SetKeyWithIV((const CryptoPP::byte*)key.data(), 32, (const CryptoPP::byte*)iv.data());

        ifstream inImage(input_path, ios::binary);
        ofstream outImage(output_path, ios::binary);

        // Se abren las imágenes
        if (!inImage.is_open() || !outImage.is_open()) {
            cerr << "Error al abrir las imágenes" << endl;
            return;
        }

        // Se declara el hash que permitirá verificar la integridad de la imagen
        SHA256 sha;
        processBatch(inImage, outImage, sha, enc);

        // Se calcula el hash de toda la imagen
        CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
        sha.Final(hash);

        // Se codifica el hash resultante para visualizarlo como hexadecimal
        string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(hash, sizeof(hash));
        encoder.MessageEnd();

        // Preparar el mensaje para cifrar (semilla y hash)
        string messageToEncrypt;
        messageToEncrypt.append(reinterpret_cast<const char*>(&seed), sizeof(seed));
        messageToEncrypt.append(hashResult);

        //Se carga la llave pública
        RSA::PublicKey publicKey;
        StringSource ssPublicKey(RSA_PUBLIC_KEY, true, new Base64Decoder);
        publicKey.BERDecode(ssPublicKey);

        //Se cifra la semilla y el hash con RSA
        string encryptedMessage;
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        StringSource ss(messageToEncrypt, true,
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(encryptedMessage)
            )
        );

        // Escribir el cifrado asimétrico cifrada en el archivo de salida
        outImage.write(encryptedMessage.data(), encryptedMessage.size());
        // Se cierran las imágenes
        inImage.close();
        outImage.close();


    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
    }
    cout << "Encrypted image" << endl;
}

void decrypt(const string& input_path, const string& output_path) {

    ifstream inImage(input_path, ios::binary);
    ofstream outImage(output_path, ios::binary);

    if (!inImage.is_open() || !outImage.is_open()) {
        cerr << "Error al abrir las imágenes." << endl;
        return;
    }

    // Mover el cursor del archivo hasta el final menos el tamaño de lo cifrado con RSA (256 bytes)
    inImage.seekg(0, ios::end);
    streampos fileSize = inImage.tellg();
    size_t encryptedRSASize = 256;

    // Leer el cifrado asimétrico al final del archivo
    inImage.seekg(static_cast<streamsize>(fileSize) - static_cast<streamsize>(encryptedRSASize), ios::beg);
    string encryptedRSA(encryptedRSASize, '\0');
    inImage.read(&encryptedRSA[0], encryptedRSASize);

    // Calcular el tamaño de los datos cifrados
    streamsize encryptedDataSize = static_cast<streamsize>(fileSize) - static_cast<streamsize>(encryptedRSASize);
    // Volver al punto donde empiezan los datos cifrados
    inImage.seekg(0, ios::beg);
    
    // Se carga la llave privada
    RSA::PrivateKey privateKey;
    StringSource ssPrivateKey(RSA_PRIVATE_KEY, true, new Base64Decoder);
    privateKey.BERDecode(ssPrivateKey);

    // Se descifra el cifrado asimétrico
    string decryptedMessage;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    StringSource ss(encryptedRSA, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(decryptedMessage)
        )
    );

    // Leer la semilla desde el archivo de entrada
    uint16_t seed;
    string originalHash;
    memcpy(&seed, decryptedMessage.data(), sizeof(seed));
    originalHash = decryptedMessage.substr(sizeof(seed));

    // Se genera la llave y el vector de inicialización para desencriptar a partir de la semilla leída
    string key = generateDynamicKey(seed);
    string iv = generateDynamicIV(seed);

    // Se solicitan las rutas de la imagen encriptada y la imagen desencriptada
    cout << "input_path=" << input_path << endl;
    cout << "output_path=" << output_path << endl;

    auto processBatch = [](ifstream& inImage, ofstream& outImage, SHA256& sha, CTR_Mode<AES>::Decryption& dec, streamsize encryptedDataSize) {
        // Se declara el tamaño del buffer para leer las imágenes en batches
        vector<CryptoPP::byte> buffer(BATCH_SIZE);

        // Procesar los datos cifrados, excluyendo el hash
        streamsize totalProcessed = 0;
        while (totalProcessed < encryptedDataSize) {
            // Leer un batch, pero no exceder los datos cifrados
            streamsize bytesToProcess = min(static_cast<streamsize>(BATCH_SIZE), encryptedDataSize - totalProcessed);
            // Se lee un batch de la imagen encriptada
            inImage.read(reinterpret_cast<char*>(buffer.data()), bytesToProcess);
            streamsize bytesProcesados = inImage.gcount();
            if (bytesProcesados > 0) {
                vector<CryptoPP::byte> decrypted(bytesProcesados);
                // Se descifra el batch encriptado
                dec.ProcessData(decrypted.data(), buffer.data(), bytesProcesados);
                // Se calcula el hash del batch para verificar la integridad
                sha.Update(decrypted.data(), bytesProcesados);
                // Se guarda el batch desencriptado en la imagen de salida
                outImage.write(reinterpret_cast<char*>(decrypted.data()), bytesProcesados);
                totalProcessed += bytesProcesados;
            }
        }
    };

    try {
        // Se declara el método de descifrado como AES con el cifrado por bloques CTR
        CTR_Mode<AES>::Decryption dec;
        // Se le asignan las llaves y el vector de inicialización generados
        dec.SetKeyWithIV((const CryptoPP::byte*)key.data(), 32, (const CryptoPP::byte*)iv.data());

        // Se declara el hash que permitirá verificar la integridad de la imagen
        SHA256 sha;
        processBatch(inImage, outImage, sha, dec, encryptedDataSize);

        // Se cierran las imágenes
        inImage.close();
        outImage.close();

        // Se calcula el hash de toda la imagen desencriptada
        CryptoPP::byte hash[CryptoPP::SHA256::DIGESTSIZE];
        sha.Final(hash);
        
        // Se guarda el hash en hexadecimal para compararlo con el hash original
        string hashResult;
        CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashResult));
        encoder.Put(hash, sizeof(hash));
        encoder.MessageEnd();
        // Se compara el hash de la imagen original con el hash de la imagen desencriptada
        if (originalHash != hashResult) {
            cerr << "La imagen fue alterada" << endl;
        }
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
    }
    cout << "Decrypted image" << endl;
}