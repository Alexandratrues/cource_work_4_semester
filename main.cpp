#include "ciphers.h"

int main()
{
    try
    {
        int choice;
        inputChoice(choice);

        std::string inputFile = "test_txt.txt";
        std::string ext = getFileExtension(inputFile);
        std::string encryptedFile = "encrypted" + ext;

        std::string keyStr = "Wz7!qP9#mR1$vX4^kL8&nJ2*tG5";
        std::vector<char> key = strToVector(keyStr);
        std::string ivStr = "Wz#6hN1(yU)4pM7d_F2+xQ9=sA5";
        std::vector<char> iv = strToVector(ivStr);

        std::ifstream fin(inputFile, std::ios::binary);
        std::ofstream fout(encryptedFile, std::ios::binary);
        checkInputFile(fin);
        checkOutputFile(fout);

        if (ext == ".bmp")
        {
            std::vector<char> header(54);
            fin.read(header.data(), 54);
            fout.write(header.data(), 54);
        }

        menu(choice, fin, fout, key, iv, true);
        fin.close();
        fout.close();


        std::ifstream encIn(encryptedFile, std::ios::binary);
        std::string decryptedFile = "decrypted" + ext;
        std::ofstream decFile(decryptedFile, std::ios::binary);
        checkInputFile(encIn);
        checkOutputFile(decFile);


        if (ext == ".bmp")
        {
            std::vector<char> header(54);
            encIn.read(header.data(), 54);
            decFile.write(header.data(), 54);
        }

        menu(choice, encIn, decFile, key, iv, false);
        encIn.close();
        decFile.close();
    }
    catch (const std::invalid_argument& e) { std::cerr << e.what() << "\n"; }

    return 0;
}
