#ifndef CIFERS_H
#define CIFERS_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <iomanip>

const int BLOCK_SIZE = 16;


unsigned char rotl(unsigned char v, int n);
unsigned char rotr(unsigned char v, int n);

void inputChoice(int& choice);
std::vector<char> strToVector(const std::string& str);
void checkInputFile(std::ifstream& fin);
void checkOutputFile(std::ofstream& fout);
std::string getFileExtension(const std::string& filename);
void menu(int choice, std::ifstream& fin, std::ofstream& fout, const std::vector<char>& key, const std::vector<char>& iv, bool encrypt);


void encryptXorBlock(const std::vector<char>& input, std::vector<char>& output, const std::vector<char>& key);
void decryptXorBlock(const std::vector<char>& input, std::vector<char>& output, const std::vector<char>& key);
void xorBlocks(const std::vector<char>& a, const std::vector<char>& b, std::vector<char>& result);

void encryptECB(std::istream& fin, std::ostream& fout, const std::vector<char>& key);
void decryptECB(std::istream& fin, std::ostream& fout, const std::vector<char>& key);
void encryptCBC(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv);
void decryptCBC(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv);


void xorCounter(const std::vector<char>& input, std::vector<char>& output, const std::vector<char>& key);
void incrementCounter(std::vector<char>& counter);

void processCTR(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv);
void processGCM(std::istream& fin, std::ostream& fout, const std::vector<char>& key, const std::vector<char>& iv, std::vector<char>& tag, bool encrypting);

#endif
