/*
 * Copyright (c) 2019 xfwcfw
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "keystore.h"
#include <fstream>
#include <vector>
#include <sstream>
#include <iostream>

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

int char2int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

std::string hex2bin(const std::string &src)
{
    std::string hex;
    for (unsigned long i = 0; i < src.size(); i += 2) {
        char chr = char2int(src[i]) << 4 | char2int(src[i + 1]);
        hex += chr;
    }
    return hex;
}

KeyStoreType KeyStoreNameToType(std::string name)
{
    if (name == "Retail")
        return KeyStoreType::Retail;
    else if (name == "Dev")
        return KeyStoreType::Dev;
    else if (name == "Proto")
        return KeyStoreType::Proto;
    else if (name == "Arcade")
        return KeyStoreType::Arcade;
    else
        return KeyStoreType::Max;
}

bool KeyStore::IsValid()
{
    // Check if all required keys are set.
    if (this->SignatureMasterKey.size() == 0 || this->SignatureHashKey.size() == 0 ||
        this->KbitMasterKey.size() == 0 || this->KbitIV.size() == 0 ||
        this->KcMasterKey.size() == 0 || this->KcIV.size() == 0 ||
        this->RootSignatureMasterKey.size() == 0 || this->RootSignatureHashKey.size() == 0 ||
        this->ContentTableIV.size() == 0 || this->ContentIV.size() == 0)
    {
        return false;
    }
    else if (this->type == KeyStoreType::Arcade && (this->ArcadeKbit.size() == 0 || this->ArcadeKc.size() == 0))
    {
        return false;
    }

    return true;
}

int KeyStoreManager::Load(std::string filename)
{
    CSimpleIniA iniParser;

    // Open and parse the ini keystore file.
    SI_Error ret = iniParser.LoadFile(filename.c_str());
    if (ret < 0)
        return KEYSTORE_ERROR_OPEN_FAILED;

    // Get a list of all sections.
    CSimpleIniA::TNamesDepend sections;
    iniParser.GetAllSections(sections);

    // Loop and create a new keystore for each section.
    for (auto section = sections.begin(); section != sections.end(); section++)
    {
        // Get the keystore type for this section.
        KeyStoreType type = KeyStoreNameToType(section->pItem);
        if (type == KeyStoreType::Max)
            continue;

        // Get all the keys in the section.
        CSimpleIniA::TNamesDepend sectionKeys;
        iniParser.GetAllKeys(section->pItem, sectionKeys);

        // Initialize the keystore and parse key values.
        KeyStore& keystore = this->keystores[(int)type];
        keystore.type = type;

        for (auto keypair = sectionKeys.begin(); keypair != sectionKeys.end(); keypair++)
        {
            std::string key = keypair->pItem;
            std::string value = iniParser.GetValue(section->pItem, keypair->pItem);

            if (value.size() % 2 != 0)
                return KEYSTORE_ERROR_ODD_LEN_VALUE;

            value = hex2bin(value);

            if (key == "MG_SIG_MASTER_KEY")
                keystore.SignatureMasterKey = value;
            if (key == "MG_SIG_HASH_KEY")
                keystore.SignatureHashKey = value;
            if (key == "MG_KBIT_MASTER_KEY")
                keystore.KbitMasterKey = value;
            if (key == "MG_KBIT_IV")
                keystore.KbitIV = value;
            if (key == "MG_KC_MASTER_KEY")
                keystore.KcMasterKey = value;
            if (key == "MG_KC_IV")
                keystore.KcIV = value;
            if (key == "MG_ROOTSIG_MASTER_KEY")
                keystore.RootSignatureMasterKey = value;
            if (key == "MG_ROOTSIG_HASH_KEY")
                keystore.RootSignatureHashKey = value;
            if (key == "MG_CONTENT_TABLE_IV")
                keystore.ContentTableIV = value;
            if (key == "MG_CONTENT_IV")
                keystore.ContentIV = value;

            if (type == KeyStoreType::Arcade)
            {
                if (key == "ARCADE_KBIT")
                    keystore.ArcadeKbit = value;
                if (key == "ARCADE_KC")
                    keystore.ArcadeKc = value;
            }
        }

        if (keystore.IsValid() == false)
        {
            if (keystore.GetType() != KeyStoreType::Arcade)
                printf("Key store section '%s' is missing one or required more keys\n", section->pItem);
            else
                printf("Key store section '%s' is missing one or required more keys, arcade also requires ARCADE_KBIT and ARCADE_KC\n", section->pItem);
            return KEYSTORE_ERROR_MISSING_KEY;
        }
    }

    return 0;
}

std::string KeyStoreManager::getErrorString(int err)
{
    switch (err) {
        case 0:
            return "Success";
        case KEYSTORE_ERROR_OPEN_FAILED:
            return "Failed to open keystore!";
        case KEYSTORE_ERROR_LINE_NOT_KEY_VALUE:
            return "Line in the keystore file is not key=value pair!";
        case KEYSTORE_ERROR_ODD_LEN_VALUE:
            return "Odd length hex value in keystore!";
        case KEYSTORE_ERROR_MISSING_KEY:
            return "Some keys are missing from the keystore!";
        default:
            return "Unknown error";
    }
}
