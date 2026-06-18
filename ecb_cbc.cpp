#include "ciphers.h"

void encryptXorBlock(const std::vector<char>& input, std::vector<char>& output, const std::vector<char>& key)
{
    std::vector<unsigned char> state(BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        state[i] = static_cast<unsigned char>(input[i]) ^ static_cast<unsigned char>(key[i % key.size()]);
    }

    for (int r = 0; r < 6; ++r)
    {
        for (int i = 0; i < BLOCK_SIZE; ++i)
        {
            unsigned char k = static_cast<unsigned char>(key[(i + r) % key.size()]);
            state[i] = rotl(state[i], 3) + k;
        }
    }
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        output[i] = static_cast<char>(state[i]);
    }
}
void decryptXorBlock(const std::vector<char>& input, std::vector<char>& output, const std::vector<char>& key)
{
    std::vector<unsigned char> state(BLOCK_SIZE);
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        state[i] = static_cast<unsigned char>(input[i]);
    }

    for (int r = 5; r >= 0; --r)
    {
        for (int i = BLOCK_SIZE - 1; i >= 0; --i)
        {
            unsigned char k = static_cast<unsigned char>(key[(i + r) % key.size()]);
            state[i] = rotr(state[i] - k, 3);
        }
    }
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        unsigned char k = static_cast<unsigned char>(key[i % key.size()]);
        output[i] = static_cast<char>(state[i] ^ k);
    }
}
void xorBlocks(const std::vector<char>& a, const std::vector<char>& b, std::vector<char>& result)
{
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        result[i] = a[i] ^ b[i];
    }
}

void encryptECB(std::istream& fin, std::ostream& fout, const std::vector<char>& key)
{
    std::vector<char> buffer(BLOCK_SIZE);
    std::vector<char> cipher(BLOCK_SIZE);
    while (fin.read(buffer.data(), BLOCK_SIZE) || fin.gcount() > 0)
    {
        if (fin.gcount() < BLOCK_SIZE)
        {
            std::memset(buffer.data() + fin.gcount(), 0, BLOCK_SIZE - fin.gcount());
        }
        encryptXorBlock(buffer, cipher, key);
        fout.write(cipher.data(), BLOCK_SIZE);
    }
}
void decryptECB(std::istream& fin, std::ostream& fout, const std::vector<char>& key)
{
    std::vector<char> buffer(BLOCK_SIZE);
    std::vector<char> plain(BLOCK_SIZE);
    while (fin.read(buffer.data(), BLOCK_SIZE))
    {
        decryptXorBlock(buffer, plain, key);
        fout.write(plain.data(), BLOCK_SIZE);
    }
}
void encryptCBC(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv)
{
    std::vector<char> buffer(BLOCK_SIZE);
    std::vector<char> temp(BLOCK_SIZE);
    std::vector<char> cipher(BLOCK_SIZE);
    std::vector<char> prev = iv;
    while (fin.read(buffer.data(), BLOCK_SIZE) || fin.gcount() > 0)
    {
        if (fin.gcount() < BLOCK_SIZE)
        {
            std::memset(buffer.data() + fin.gcount(), 0, BLOCK_SIZE - fin.gcount());
        }
        xorBlocks(buffer, prev, temp);
        encryptXorBlock(temp, cipher, key);
        fout.write(cipher.data(), BLOCK_SIZE);
        prev = cipher;
    }
}
void decryptCBC(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv)
{
    std::vector<char> buffer(BLOCK_SIZE);
    std::vector<char> plain(BLOCK_SIZE);
    std::vector<char> temp(BLOCK_SIZE);
    std::vector<char> prev = iv;
    while (fin.read(buffer.data(), BLOCK_SIZE))
    {
        decryptXorBlock(buffer, temp, key);
        xorBlocks(temp, prev, plain);
        fout.write(plain.data(), BLOCK_SIZE);
        prev = buffer;
    }
}
