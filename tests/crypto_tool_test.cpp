#include "gtest/gtest.h"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"
#include <filesystem>
#include <string>
#include <memory>

// --- テスト用の外部シンボルの定義 ---
// nkCryptoToolMain.cpp で定義されているグローバル変数とコールバック関数を、
// テスト実行可能ファイル用にここでダミーとして定義します。
std::string global_passphrase_for_pem_cb;

int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag; // 未使用の引数
    (void)userdata; // 未使用の引数
    std::string passphrase = "test_password"; // テスト用の固定パスワード
    if (passphrase.length() > static_cast<unsigned int>(size)) {
        return 0;
    }
    memcpy(buf, passphrase.c_str(), passphrase.length());
    return static_cast<int>(passphrase.length());
}
// ---

// テストフィクスチャ: 共通のセットアップと後処理をまとめるクラス
class CryptoToolTest : public ::testing::Test {
protected:
    // 各テストケースの実行前に呼ばれる
    void SetUp() override {
        test_key_dir = "temp_test_keys";
        // 既存の場合に備えて一度削除し、再作成する
        std::filesystem::remove_all(test_key_dir);
        std::filesystem::create_directory(test_key_dir);
    }

    // 各テストケースの実行後に呼ばれる
    void TearDown() override {
        // テストで作成したファイルをクリーンアップ
        std::filesystem::remove_all(test_key_dir);
    }

    std::filesystem::path test_key_dir;
};

// TEST_Fマクロでテストフィクスチャを使用したテストケースを定義
TEST_F(CryptoToolTest, ECC_ObjectCreationAndKeyPath) {
    auto tool = std::make_unique<nkCryptoToolECC>();
    ASSERT_NE(tool, nullptr) << "ECCツールのインスタンス化に失敗しました。";

    tool->setKeyBaseDirectory(test_key_dir);
    ASSERT_EQ(tool->getEncryptionPublicKeyPath(), test_key_dir / "public_enc_ecc.key");
    ASSERT_EQ(tool->getSigningPrivateKeyPath(), test_key_dir / "private_sign_ecc.key");
}

TEST_F(CryptoToolTest, ECC_GenerateEncryptionKeyPair) {
    auto tool = std::make_unique<nkCryptoToolECC>();
    tool->setKeyBaseDirectory(test_key_dir);

    auto pub_key_path = tool->getEncryptionPublicKeyPath();
    auto priv_key_path = tool->getEncryptionPrivateKeyPath();

    bool result = tool->generateEncryptionKeyPair(pub_key_path, priv_key_path, "test_password");

    ASSERT_TRUE(result) << "ECC暗号化キーペアの生成に失敗しました。";
    ASSERT_TRUE(std::filesystem::exists(pub_key_path)) << "公開鍵ファイルが作成されませんでした。";
    ASSERT_TRUE(std::filesystem::exists(priv_key_path)) << "秘密鍵ファイルが作成されませんでした。";
}

TEST_F(CryptoToolTest, PQC_ObjectCreationAndKeyPath) {
    auto tool = std::make_unique<nkCryptoToolPQC>();
    ASSERT_NE(tool, nullptr) << "PQCツールのインスタンス化に失敗しました。";

    tool->setKeyBaseDirectory(test_key_dir);
    ASSERT_EQ(tool->getEncryptionPublicKeyPath(), test_key_dir / "public_enc_pqc.key");
    ASSERT_EQ(tool->getSigningPrivateKeyPath(), test_key_dir / "private_sign_pqc.key");
}

TEST_F(CryptoToolTest, PQC_GenerateSigningKeyPair) {
    auto tool = std::make_unique<nkCryptoToolPQC>();
    tool->setKeyBaseDirectory(test_key_dir);

    auto pub_key_path = tool->getSigningPublicKeyPath();
    auto priv_key_path = tool->getSigningPrivateKeyPath();

    bool result = tool->generateSigningKeyPair(pub_key_path, priv_key_path, "test_password");

    ASSERT_TRUE(result) << "PQC署名キーペアの生成に失敗しました。";
    ASSERT_TRUE(std::filesystem::exists(pub_key_path)) << "公開鍵ファイルが作成されませんでした。";
    ASSERT_TRUE(std::filesystem::exists(priv_key_path)) << "秘密鍵ファイルが作成されませんでした。";
}
