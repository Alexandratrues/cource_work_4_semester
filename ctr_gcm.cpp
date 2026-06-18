#include "ciphers.h"

void xorCounter(const std::vector<char>& input, std::vector<char>& output, const std::vector<char>& key)
{
    std::vector<unsigned char> state(BLOCK_SIZE);
    unsigned char checksum = 0;

    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        state[i] = (unsigned char)input[i] ^ (unsigned char)key[i % key.size()];
        checksum ^= state[i];
    }

    for (int r = 0; r < 6; ++r)
    {
        for (int i = 0; i < BLOCK_SIZE; ++i)
        {
            state[i] = rotl(state[i] ^ checksum, 3);
            state[i] += (unsigned char)key[(i + r) % key.size()];
            checksum = rotl(checksum ^ state[i], 1);
        }
    }

    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        output[i] = (char)state[i];
    }
}
void incrementCounter(std::vector<char>& counter)
{
    for (int i = BLOCK_SIZE - 1; i >= 0; --i)
    {
        unsigned char& byte = (unsigned char&)counter[i];
        ++byte;
        if (byte != 0)
        {
            return;
        }
    }
}

void processCTR(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv)
{
    std::vector<char> buffer(BLOCK_SIZE);
    std::vector<char> keystream(BLOCK_SIZE);
    std::vector<char> cipher_out(BLOCK_SIZE);
    std::vector<char> counter = iv;

    while (fin.read(buffer.data(), BLOCK_SIZE) || fin.gcount() > 0)
    {
        std::streamsize bytes = fin.gcount();
        if (bytes <= 0) break;

        xorCounter(counter, keystream, key);

        for (int i = 0; i < bytes; ++i)
        {
            cipher_out[i] = buffer[i] ^ keystream[i];
        }

        fout.write(cipher_out.data(), bytes);

        incrementCounter(counter);
    }
}
void processGCM(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv, std::vector<char>& tag, bool encrypting)
{
    std::vector<char> buffer(BLOCK_SIZE);
    std::vector<char> keystream(BLOCK_SIZE);
    std::vector<char> cipher_out(BLOCK_SIZE);
    std::vector<char> counter = iv;
    tag.assign(BLOCK_SIZE, 0);

    while (fin.read(buffer.data(), BLOCK_SIZE) || fin.gcount() > 0)
    {
        std::streamsize bytes = fin.gcount();
        if (bytes <= 0) break;

        xorCounter(counter, keystream, key);

        for (int i = 0; i < bytes; ++i)
        {
            char ciphertext_byte;
            if (encrypting)
            {
                ciphertext_byte = buffer[i] ^ keystream[i];
                cipher_out[i] = ciphertext_byte;
            }
            else
            {
                ciphertext_byte = buffer[i];
                cipher_out[i] = ciphertext_byte ^ keystream[i];
            }
            tag[i % BLOCK_SIZE] ^= ciphertext_byte;
        }

        fout.write(cipher_out.data(), bytes);

        incrementCounter(counter);
    }
}
