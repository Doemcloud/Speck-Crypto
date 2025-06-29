#include <iostream>
#include <cstdint>
#include <vector>
#include <cstring>

using namespace std;

class Speck {
private:

    uint32_t alpha = 3;
    uint32_t beta = 8;
    uint32_t rounds = 32;

    uint64_t rotate_left(uint64_t x, uint32_t n) {
        return (x << n) | (x >> (64 - n));
    }

    uint64_t rotate_right(uint64_t x, uint32_t n) {
        return (x >> n) | (x << (64 - n));
    }

    void speck_round(uint64_t &x, uint64_t &y, uint64_t k) {
        x = rotate_right(x, beta);
        x += y;
        x ^= k;
        y = rotate_left(y, alpha);
        y ^= x;
    }

    void speck_inv_round(uint64_t &x, uint64_t &y, uint64_t k) {
        y ^= x;
        y = rotate_right(y, alpha);
        x ^= k;
        x -= y;
        x = rotate_left(x, beta);
    }

public:

    vector<uint64_t> key_schedule(const vector<uint64_t> &key) {
        vector<uint64_t> round_keys(rounds);
        uint64_t l = key[1];
        uint64_t k = key[0];

        round_keys[0] = k;
        for (uint32_t i = 0; i < rounds - 1; ++i) {
            l = rotate_left(l, alpha);
            l ^= k;
            k = rotate_right(k, beta);
            k ^= (i + 1);
            round_keys[i + 1] = k;
        }
        return round_keys;
    }

    vector<uint8_t> string_to_bytes(const string &text) {
        return vector<uint8_t>(text.begin(), text.end());
    }

    vector<pair<uint64_t, uint64_t>> bytes_to_blocks(const vector<uint8_t> &bytes) {
        vector<pair<uint64_t, uint64_t>> blocks;
        size_t num_blocks = (bytes.size() + 15) / 16;
        blocks.resize(num_blocks, {0, 0});

        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i % 16 < 8) {
                blocks[i / 16].first |= static_cast<uint64_t>(bytes[i]) << ((i % 8) * 8);
            } else {
                blocks[i / 16].second |= static_cast<uint64_t>(bytes[i]) << (((i % 8) - 8) * 8);
            }
        }
        return blocks;
    }

    vector<uint8_t> blocks_to_bytes(const vector<pair<uint64_t, uint64_t>> &blocks) {
        vector<uint8_t> bytes;
        bytes.reserve(blocks.size() * 16);

        for (const auto &block : blocks) {
            for (int i = 0; i < 8; ++i) {
                bytes.push_back(static_cast<uint8_t>((block.first >> (i * 8)) & 0xFF));
            }
            for (int i = 0; i < 8; ++i) {
                bytes.push_back(static_cast<uint8_t>((block.second >> (i * 8)) & 0xFF));
            }
        }
        return bytes;
    }

    string encrypt_text(const string &plaintext, const vector<uint64_t> &round_keys) {
        vector<uint8_t> plaintext_bytes = string_to_bytes(plaintext);
        vector<pair<uint64_t, uint64_t>> blocks = bytes_to_blocks(plaintext_bytes);

        while (blocks.size() % 2 != 0) {
            blocks.push_back({0, 0});
        }

        for (auto &[x, y] : blocks) {
            for (uint32_t i = 0; i < rounds; ++i) {
                speck_round(x, y, round_keys[i]);
            }
        }

        vector<uint8_t> ciphertext = blocks_to_bytes(blocks);
        return string(ciphertext.begin(), ciphertext.end());
    }

    string decrypt_text(const string &ciphertext, const vector<uint64_t> &round_keys) {
        vector<uint8_t> ciphertext_bytes = string_to_bytes(ciphertext);
        vector<pair<uint64_t, uint64_t>> blocks = bytes_to_blocks(ciphertext_bytes);

        for (auto &[x, y] : blocks) {
            for (int i = rounds - 1; i >= 0; --i) {
                speck_inv_round(x, y, round_keys[i]);
            }
        }

        vector<uint8_t> plaintext_bytes = blocks_to_bytes(blocks);

        while (!plaintext_bytes.empty() && plaintext_bytes.back() == 0) {
            plaintext_bytes.pop_back();
        }

        return string(plaintext_bytes.begin(), plaintext_bytes.end());
    }
};

vector<uint64_t> transformKey(const string &key_str) {
    if (key_str.size() != 16) {
        cerr << "Ошибка: ключ должен быть длиной 16 символов." << endl;
        exit(1);
    }

    vector<uint64_t> key(2);
    key[0] = 0;
    key[1] = 0;

    for (size_t i = 0; i < 8; ++i) {
        key[0] |= static_cast<uint64_t>(static_cast<uint8_t>(key_str[i])) << (i * 8);
    }
    for (size_t i = 0; i < 8; ++i) {
        key[1] |= static_cast<uint64_t>(static_cast<uint8_t>(key_str[i + 8])) << (i * 8);
    }

    return key;
}




int main() {
    Speck speck;


    string key_str;
    cout << "Введите 16-символьный ключ: ";
    getline(cin, key_str);

    vector<uint64_t> key = transformKey(key_str);
    vector<uint64_t> round_keys = speck.key_schedule(key);

    string plaintext;
    cout << "Введите текст: ";
    getline(cin, plaintext);

    string ciphertext = speck.encrypt_text(plaintext, round_keys);
    cout << "encrypt_text (hex): ";
    for (unsigned char c : ciphertext) {
        printf("%02x", c);
    }
    cout << endl;

    string decrypted = speck.decrypt_text(ciphertext, round_keys);
    cout << "decrypt_text: " << decrypted << endl;

    return 0;
}
