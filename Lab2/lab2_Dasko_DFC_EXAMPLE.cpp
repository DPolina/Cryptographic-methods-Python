
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <algorithm>
#include <limits>

#include <cctype>
#include <random>
#include <chrono>
#include <cstdint>
#include <array>

constexpr size_t KEY_SIZE = 256; // in bits
constexpr size_t BLOCK_SIZE = 128; // in bits

enum class Mode {
    ECB, CBC, PCBC, CFB, OFB, CTR
};

enum class PaddingMethod {
    ANSI_X923, ISO_10126, PKCS7, ISO_IEC_7816_4
};

std::vector<uint64_t> readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Unable to open file: " + filename);
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint64_t> data(fileSize / sizeof(uint64_t) + (fileSize % sizeof(uint64_t) ? 1 : 0));
    file.read(reinterpret_cast<char*>(data.data()), fileSize);

    return data;
}

void writeBinaryFile(const std::string& filename, const std::vector<uint64_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Unable to open file for writing: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size() * sizeof(uint64_t));
}

std::vector<uint64_t> generateRandomData(size_t size) {
    std::vector<uint64_t> data(size);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    for (auto& element : data) {
        element = dis(gen);
    }

    return data;
}


//Паддинги
std::vector<uint64_t> padData(const std::vector<uint64_t>& data, PaddingMethod method) {
    size_t blockSizeBytes = BLOCK_SIZE / 8;
    size_t dataSize = data.size() * sizeof(uint64_t);
    size_t paddingSize = blockSizeBytes - (dataSize % blockSizeBytes);
    if (paddingSize == 0) paddingSize = blockSizeBytes;

    std::vector<uint8_t> paddedData(reinterpret_cast<const uint8_t*>(data.data()),
        reinterpret_cast<const uint8_t*>(data.data()) + dataSize);

    switch (method) {
    case PaddingMethod::ANSI_X923:
        paddedData.insert(paddedData.end(), paddingSize - 1, 0);
        paddedData.push_back(static_cast<uint8_t>(paddingSize));
        break;
    case PaddingMethod::ISO_10126:
    {
        std::vector<uint64_t> randomPadding = generateRandomData((paddingSize - 1 + 7) / 8);
        paddedData.insert(paddedData.end(),
            reinterpret_cast<uint8_t*>(randomPadding.data()),
            reinterpret_cast<uint8_t*>(randomPadding.data()) + paddingSize - 1);
    }
    paddedData.push_back(static_cast<uint8_t>(paddingSize));
    break;
    case PaddingMethod::PKCS7:
        paddedData.insert(paddedData.end(), paddingSize, static_cast<uint8_t>(paddingSize));
        break;
    case PaddingMethod::ISO_IEC_7816_4:
        paddedData.push_back(0x80);
        paddedData.insert(paddedData.end(), paddingSize - 1, 0);
        break;
    }

    std::vector<uint64_t> result((paddedData.size() + 7) / 8);
    std::copy(reinterpret_cast<uint64_t*>(paddedData.data()),
        reinterpret_cast<uint64_t*>(paddedData.data() + paddedData.size()),
        result.begin());
    return result;
}

std::vector<uint64_t> removePadding(const std::vector<uint64_t>& data, PaddingMethod method) {
    std::vector<uint8_t> paddedData(reinterpret_cast<const uint8_t*>(data.data()),
        reinterpret_cast<const uint8_t*>(data.data()) + data.size() * sizeof(uint64_t));
    size_t paddingSize;

    switch (method) {
    case PaddingMethod::ANSI_X923:
    case PaddingMethod::ISO_10126:
    case PaddingMethod::PKCS7:
        paddingSize = paddedData.back();
        if (paddingSize == 0 || paddingSize > BLOCK_SIZE / 8) {
            throw std::runtime_error("Invalid padding");
        }
        break;
    case PaddingMethod::ISO_IEC_7816_4:
    {
        auto it = std::find(paddedData.rbegin(), paddedData.rend(), 0x80);
        if (it == paddedData.rend()) {
            throw std::runtime_error("Invalid padding");
        }
        paddingSize = std::distance(paddedData.rbegin(), it) + 1;
    }
    break;
    }

    if (method == PaddingMethod::PKCS7) {
        if (!std::all_of(paddedData.end() - paddingSize, paddedData.end(),
            [paddingSize](uint8_t b) { return b == paddingSize; })) {
            throw std::runtime_error("Invalid PKCS7 padding");
        }
    }

    paddedData.resize(paddedData.size() - paddingSize);

    std::vector<uint64_t> result((paddedData.size() + 7) / 8);
    std::copy(reinterpret_cast<uint64_t*>(paddedData.data()),
        reinterpret_cast<uint64_t*>(paddedData.data() + paddedData.size()),
        result.begin());
    return result;
}




//Feistel function definition
std::vector<uint64_t> FeistelFunction(const std::vector<uint64_t>& input, const std::vector<uint64_t>& roundKey) {
    // Calculate the size of each half of the block
    
    uint64_t X(input[0]);
    uint64_t A(roundKey[0]);
    uint64_t B(roundKey[1]);
    
    //метод для произведения 64-битных чисел  
    auto multiply_uint64 = [](uint64_t X, uint64_t A) {
        uint64_t low = 0, high = 0;

        uint32_t x0 = static_cast<uint32_t>(X);
        uint32_t x1 = static_cast<uint32_t>(X >> 32);
        uint32_t a0 = static_cast<uint32_t>(A);
        uint32_t a1 = static_cast<uint32_t>(A >> 32);

        uint64_t p00 = static_cast<uint64_t>(x0) * a0;
        uint64_t p01 = static_cast<uint64_t>(x0) * a1;
        uint64_t p10 = static_cast<uint64_t>(x1) * a0;
        uint64_t p11 = static_cast<uint64_t>(x1) * a1;

        low = p00;
        high = p11;

        uint64_t mid = p01 + p10;
        high += (mid >> 32);

        uint64_t mid_low = (mid << 32);
        low += mid_low;
        if (low < mid_low) {
            high++;
        }

        return std::pair<uint64_t, uint64_t>(low, high);
    };
    auto result = multiply_uint64(X, A);
    
    uint64_t low_result = result.first;
    uint64_t high_result = result.second;

    //корректное сложение с B
    uint64_t old_low = low_result;
    low_result += B;
    if (low_result < old_low) {
        high_result++;
    }

    // 2^64 ≡ -13 (mod 2^64+13)
    //поэтому low_result + high_result * 2^64 ≡ low_result + high_result * -13 ≡ low_result - 13 * high_result (mod 2^64+13)
    //для получения (mod 2^64) этот результат мы бы обрезали с конца, а по факту просто не учитываем биты переполнения

    uint64_t Z = low_result - high_result*13;

    std::vector<uint32_t> RT = {
    0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7, 0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef,
    0x324e7738, 0x926cfbe5, 0xf4bf8d8d, 0x8c31d763, 0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59594,
    0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce, 0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf,
    0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4, 0xc2d3293d, 0x20e9e5ea, 0xf02ac60a, 0xcc93ed87,
    0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0, 0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
    0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3, 0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe,
    0x393c48cb, 0xbbca060f, 0x0ff8ec6d, 0x31beb5cc, 0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb,
    0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73, 0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe6700831
    };

    // Разбиваем на две половины
    uint32_t Z_l = static_cast<uint32_t>(Z >> 32);
    uint32_t Z_r = static_cast<uint32_t>(Z & 0xFFFFFFFF);

    // Собираем обратно
    uint64_t Y = ( (static_cast<uint64_t>(Z_r^RT[Z_l&0x3F]) << 32) | (Z_l ^ static_cast <uint32_t>(0xeb64749aULL) ) ) 
        + static_cast <uint64_t>(0x86d1bf275b9b251dULL);

    return std::vector<uint64_t>{Y};
}

std::vector<uint64_t> TaktProcessing(std::vector<uint64_t> block, std::vector<uint64_t> roundKey, bool encrypt) {
    // Calculate the size of each half of the block
    const size_t HALF_SIZE = BLOCK_SIZE / (64*2);

    // Split the block into left and right halves
    std::vector<uint64_t> left(block.begin(), block.begin() + HALF_SIZE);
    std::vector<uint64_t> right(block.begin() + HALF_SIZE, block.end());

    if (encrypt) {
        // Encryption: R' = L ^ F(R, K), L' = R
        std::vector<uint64_t> new_right = left;
        std::vector<uint64_t> f_result = FeistelFunction(right, roundKey);
        for (size_t i = 0; i < HALF_SIZE; ++i) {
            new_right[i] ^= f_result[i];
        }
        left = std::move(right);
        right = std::move(new_right);
    }
    else {
        // Decryption: L' = R ^ F(L, K), R' = L
        std::vector<uint64_t> new_left = right;
        std::vector<uint64_t> f_result = FeistelFunction(left, roundKey);
        for (size_t i = 0; i < HALF_SIZE; ++i) {
            new_left[i] ^= f_result[i];
        }
        right = std::move(left);
        left = std::move(new_left);
    }

    // Combine left and right halves
    std::vector<uint64_t> result;
    result.reserve(BLOCK_SIZE);
    result.insert(result.end(), left.begin(), left.end());
    result.insert(result.end(), right.begin(), right.end());

    return result;
}

std::vector<std::vector<uint64_t>> generateRoundKeys(const std::vector<uint64_t>& K, size_t rounds) {
    
    std::vector<std::vector<uint64_t>> roundKeys(rounds);

    // ШАГ 1
    static const std::vector<uint64_t> KS = { 
        0xda06c80abb1185ebULL, 
        0x4f7c7b5757f59584ULL, 
        0x90cfd47d7c19bb42ULL, 
        0x158d9554f7b46bceULL 
    };
    

    //PK <- trunk_{256}(key|KS)
    std::vector<uint64_t> PK(4, 0); // 256 bits = 4 * 64 bits
    for (int i = 0; i < KEY_SIZE/64; i++)PK[i] = K[i]; 
    for (int i = KEY_SIZE / 64; i < 4; i++)PK[i] = KS[i - KEY_SIZE / 64];
    

    //PK разрезать на блоки по 32
    std::vector<uint64_t> PK32(8, 0);
    for (size_t i = 0; i < 4; ++i) {
        PK32[i * 2] = (PK[i] >> 32);
        PK32[i * 2 + 1] = (PK[i] & 0xFFFFFFFF);
    }

    //ШАГ 2

    static const std::vector<uint64_t> KA = { 0, 0xb7e151628aed2a6aULL, 0xbf7158809cf4f3c7ULL, 0x62e7160f38b4da56ULL };
    static const std::vector<uint64_t> KB = { 0, 0xa784d9045190cfefULL, 0x324e7738926cfbe5ULL, 0xf4bf8d8d8c31d763ULL };

    std::vector<uint64_t> OA(4,0);
    std::vector<uint64_t> OB(4, 0);
    std::vector<uint64_t> EA(4, 0);
    std::vector<uint64_t> EB(4, 0);

    OA[0] = PK32[0] | (PK32[7] << 32);
    OB[0] = PK32[4] | (PK32[3] << 32);
    EA[0] = PK32[1] | (PK32[6] << 32);
    EB[0] = PK32[5] | (PK32[2] << 32);

    for (int i = 1; i != 4; i++) {
        OA[i] = OA[0] ^ KA[i];
        OB[i] = OB[0] ^ KB[i];
        EA[i] = EA[0] ^ KA[i];
        EB[i] = EB[0] ^ KB[i];
    }
    
    //ШАГ 3
    std::vector<uint64_t> OK(8, 0);
    for (int i = 0; i < 4; i++) {
        OK[2 * i] = OA[i];
        OK[2 * i + 1] = OB[i];
    }
    std::vector<uint64_t> EK(8, 0);
    for (int i = 0; i < 4; i++) {
        EK[2 * i] = EA[i];
        EK[2 * i + 1] = EB[i];
    }

    std::vector<std::vector<uint64_t>> TaktKeys(8, std::vector<uint64_t>(2, 0));
    std::vector<uint64_t> initText(2, 0);
    for (size_t i = 0; i != 8; i++) {
        if (i != 0) {
            initText = TaktKeys[i - 1];
        }
        
        //четырехраундовое шифрование
        for (size_t n = 0; n != 4; n++) {
            if (i & 1) { //изза смещения индекса на 1 четность обратная от оригинальной
                initText = TaktProcessing(initText, std::vector<uint64_t>{EK[2 * n], EK[2 * n + 1]}, true);
            }
            else {
                initText = TaktProcessing(initText, std::vector<uint64_t>{OK[2 * n], OK[2 * n + 1]}, true);
            }
        }
        TaktKeys[i] = initText;
        
    }
    
    return TaktKeys;
}

std::vector<uint64_t> encryptDecrypt(const std::vector<uint64_t>& input, const std::vector<uint64_t>& key, bool encrypt, Mode mode, const std::vector<uint64_t>& sync) {
    const size_t rounds = 8; //Количество тактов шифрования
    const size_t blockSize = BLOCK_SIZE / 64; // Размер блока в uint64_t
    const size_t roundKeySize = BLOCK_SIZE / 64; // Размер тактового ключа равен размеру блока

    std::vector<std::vector<uint64_t>> roundKeys = generateRoundKeys(key, rounds);
    std::vector<uint64_t> output(input.size());
    std::vector<uint64_t> iv = sync;
    std::vector<uint64_t> counter(blockSize, 0);

    for (size_t i = 0; i < input.size(); i += blockSize) {
        std::vector<uint64_t> block(input.begin() + i, input.begin() + i + blockSize);
        std::vector<uint64_t> processedBlock;

        switch (mode) {
        case Mode::ECB:
            processedBlock = block;
            for (size_t round = 0; round < rounds; ++round) {
                processedBlock = TaktProcessing(processedBlock, roundKeys[round], encrypt);
            }
            break;

        case Mode::CBC:
            if (encrypt) {
                for (size_t j = 0; j < blockSize; ++j) {
                    block[j] ^= iv[j];
                }
                processedBlock = block;
                for (size_t round = 0; round < rounds; ++round) {
                    processedBlock = TaktProcessing(processedBlock, roundKeys[round], true);
                }
                iv = processedBlock;
            }
            else {
                processedBlock = block;
                for (size_t round = rounds; round > 0; --round) {
                    processedBlock = TaktProcessing(processedBlock, roundKeys[round - 1], false);
                }
                for (size_t j = 0; j < blockSize; ++j) {
                    processedBlock[j] ^= iv[j];
                }
                iv = block;
            }
            break;

        case Mode::PCBC:
            if (encrypt) {
                for (size_t j = 0; j < blockSize; ++j) {
                    block[j] ^= iv[j];
                }
                processedBlock = block;
                for (size_t round = 0; round < rounds; ++round) {
                    processedBlock = TaktProcessing(processedBlock, roundKeys[round], true);
                }
                for (size_t j = 0; j < blockSize; ++j) {
                    iv[j] = block[j] ^ processedBlock[j];
                }
            }
            else {
                std::vector<uint64_t> temp = block;
                processedBlock = block;
                for (size_t round = rounds; round > 0; --round) {
                    processedBlock = TaktProcessing(processedBlock, roundKeys[round - 1], false);
                }
                for (size_t j = 0; j < blockSize; ++j) {
                    processedBlock[j] ^= iv[j];
                    iv[j] = temp[j] ^ processedBlock[j];
                }
            }
            break;

        case Mode::CFB:
            processedBlock = iv;
            for (size_t round = 0; round < rounds; ++round) {
                processedBlock = TaktProcessing(processedBlock, roundKeys[round], true);
            }
            for (size_t j = 0; j < blockSize; ++j) {
                processedBlock[j] ^= block[j];
            }
            iv = encrypt ? processedBlock : block;
            break;

        case Mode::OFB:
            processedBlock = iv;
            for (size_t round = 0; round < rounds; ++round) {
                processedBlock = TaktProcessing(processedBlock, roundKeys[round], true);
            }
            iv = processedBlock;
            for (size_t j = 0; j < blockSize; ++j) {
                processedBlock[j] ^= block[j];
            }
            break;

        case Mode::CTR:
            processedBlock = counter;
            for (size_t round = 0; round < rounds; ++round) {
                processedBlock = TaktProcessing(processedBlock, roundKeys[round], true);
            }
            for (size_t j = 0; j < blockSize; ++j) {
                processedBlock[j] ^= block[j];
            }
            // Increment counter
            for (int j = blockSize - 1; j >= 0; --j) {
                if (++counter[j] != 0) break;
            }
            break;

        default:
            throw std::runtime_error("Unsupported encryption mode");
        }

        std::copy(processedBlock.begin(), processedBlock.end(), output.begin() + i);
    }

    return output;
}




//Работа с файлами
void createFileIfNotExists(const std::string& filename, size_t size) {
    std::ifstream file(filename);
    if (!file.good()) {
        std::cout << "File " << filename << " not found. Creating it with random data." << std::endl;
        auto data = generateRandomData(size);
        writeBinaryFile(filename, data);
    }
}

char getOperation() {
    char op;
    std::cout << "Select operation (e - encrypt, d - decrypt): ";
    while (true) {
        std::cin >> op;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        op = std::tolower(op);
        if (op == 'e' || op == 'd') {
            return op;
        }
        std::cout << "Invalid input. Please enter 'e' or 'd': ";
    }
}

Mode getMode() {
    std::cout << "Select encryption mode (enter number):\n"
        << "1. ECB\n2. CBC\n3. PCBC\n4. CFB\n5. OFB\n6. CTR\n";
    int choice;
    while (true) {
        std::cin >> choice;
        if (std::cin.fail() || choice < 1 || choice > 6) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter a number from 1 to 6.\n";
        }
        else {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return static_cast<Mode>(choice - 1);
        }
    }
}

PaddingMethod getPaddingMethod() {
    std::cout << "Select padding method (enter number):\n"
        << "1. ANSI X.923\n2. ISO 10126\n3. PKCS7\n4. ISO/IEC 7816-4\n";
    int choice;
    while (true) {
        std::cin >> choice;
        if (std::cin.fail() || choice < 1 || choice > 4) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input. Please enter a number from 1 to 4.\n";
        }
        else {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return static_cast<PaddingMethod>(choice - 1);
        }
    }
}


#include <cassert>
void testTaktProcessing() {
    // Тестовые данные
    std::vector<uint64_t> block = { 0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL };
    std::vector<uint64_t> roundKey = { 0xA1B2C3D4E5F6A7B8ULL, 0xC8D9E0F1A2B3C4D5ULL };


    // Шифрование
    std::vector<uint64_t> encrypted = TaktProcessing(block, roundKey, true);

    // Дешифрование
    std::vector<uint64_t> decrypted = TaktProcessing(encrypted, roundKey, false);

    // Проверка
    assert(decrypted == block && "Decryption failed: result doesn't match original data");

    std::cout << "Test passed: encryption and decryption work correctly." << std::endl;
    
    // Вывод для наглядности
    std::cout << "Original:  0x" << std::hex << block[0] << " 0x" << block[1] << std::endl;
    std::cout << "Encrypted: 0x" << std::hex << encrypted[0] << " 0x" << encrypted[1] << std::endl;
    std::cout << "Decrypted: 0x" << std::hex << decrypted[0] << " 0x" << decrypted[1] << std::endl;
}


int main() {

    char operation = getOperation();
    bool encrypt = (operation == 'e');

    Mode mode = getMode();
    PaddingMethod padding = getPaddingMethod();

    const std::string inputFile = "in.bin";
    const std::string outputFile = "out.bin";

    try {
        std::vector<uint64_t> input = readBinaryFile(inputFile);

        // Check and create key.bin if not exists
        createFileIfNotExists("key.bin", KEY_SIZE / 64);
        std::vector<uint64_t> key = readBinaryFile("key.bin");

        std::vector<uint64_t> sync;
        if (mode != Mode::ECB) {
            // Check and create sync.bin if not exists
            createFileIfNotExists("sync.bin", BLOCK_SIZE / 64);
            sync = readBinaryFile("sync.bin");
        }

        std::vector<uint64_t> processedData;

        if (encrypt) {
            std::vector<uint64_t> paddedInput = padData(input, padding);
            processedData = encryptDecrypt(paddedInput, key, true, mode, sync);
        }
        else {
            processedData = encryptDecrypt(input, key, false, mode, sync);
            processedData = removePadding(processedData, padding);
        }

        writeBinaryFile(outputFile, processedData);

        std::cout << "Operation completed successfully." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}