#include "ciphers.h"

unsigned char rotl(unsigned char v, int n)
{
    return (v << (n % 8)) | (v >> (8 - (n % 8)));
}
unsigned char rotr(unsigned char v, int n)
{
    return (v >> (n % 8)) | (v << (8 - (n % 8)));
}

void inputChoice(int& choice)
{
    std::cout << "Choose Mode:\n1. ECB\n2. CBC\n3. CTR\n4. GCM\n> ";
    std::cin >> choice;
}
std::vector<char> strToVector(const std::string& str)
{
    std::vector<char> vec(str.begin(), str.end());
    if (vec.empty())
    {
        throw std::invalid_argument("key/iv can't be empty\n");
    }
    return vec;
}
void checkInputFile(std::ifstream& fin)
{
    if (!fin.good())
    {
        throw std::invalid_argument("file doesn't exist\n");
    }
    if (!fin)
    {
        throw std::invalid_argument("input file error\n");
    }
    if (fin.peek() == EOF)
    {
        throw std::invalid_argument("file is empty\n");
    }
}
void checkOutputFile(std::ofstream& fout)
{
    if (!fout.good())
    {
        throw std::invalid_argument("file doesn't exist\n");
    }
    if (!fout)
    {
        throw std::invalid_argument("output file error\n");
    }
}
std::string getFileExtension(const std::string& filename)
{
    size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos)
    {
        return "";
    }
    return filename.substr(pos);
}
void menu(int choice, std::ifstream& fin, std::ofstream& fout, const std::vector<char>& key, const std::vector<char>& iv, bool encrypt)
{
    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();

    switch (choice)
    {
    case 1:
    {
        if (encrypt)
        {
            start = std::chrono::high_resolution_clock::now();
            encryptECB(fin, fout, key);
            end = std::chrono::high_resolution_clock::now();
            break;
        }
        start = std::chrono::high_resolution_clock::now();
        decryptECB(fin, fout, key);
        end = std::chrono::high_resolution_clock::now();
        break;
    }
    case 2:
    {
        if (encrypt)
        {
            start = std::chrono::high_resolution_clock::now();
            encryptCBC(fin, fout, key, iv);
            end = std::chrono::high_resolution_clock::now();
            break;
        }
        start = std::chrono::high_resolution_clock::now();
        decryptCBC(fin, fout, key, iv);
        end = std::chrono::high_resolution_clock::now();
        break;

    }
    case 3:
    {
        start = std::chrono::high_resolution_clock::now();
        processCTR(fin, fout, key, iv);
        end = std::chrono::high_resolution_clock::now();
        break;
    }
    case 4:
    {
        std::vector<char> tag;
        start = std::chrono::high_resolution_clock::now();
        processGCM(fin, fout, key, iv, tag, encrypt);
        end = std::chrono::high_resolution_clock::now();
        std::cout << "Tag: ";
        for (unsigned char c : tag)
        {
            std::cout << std::hex << (int)c << " ";
        }
        std::cout << std::dec << "\n";
        break;
    }
    default:
    {
        throw std::invalid_argument("Invalid choice\n");
    }
    }
    if (encrypt)
    {
        std::cout << "Enc done in: ";
    }
    else
    {
        std::cout << "Dec done in: ";
    }
    std::cout << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << " mcs\n";
}
