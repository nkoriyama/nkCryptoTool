#include "nkcrypto_ffi.hpp"
#include "CryptoConfig.hpp"
#include "CryptoProcessor.hpp"
#include <nlohmann/json.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <filesystem> // For std::filesystem::path used in CryptoProcessor construction
#include <asio.hpp> // For asio::io_context

// FFIでOperationを文字列から変換するヘルパー
Operation get_operation_from_string(const std::string& op_str) {
    if (op_str == "encrypt") return Operation::Encrypt;
    if (op_str == "decrypt") return Operation::Decrypt;
    if (op_str == "sign") return Operation::Sign;
    if (op_str == "verify") return Operation::Verify;
    if (op_str == "generate_enc_key") return Operation::GenerateEncKey;
    if (op_str == "generate_sign_key") return Operation::GenerateSignKey;
    if (op_str == "regenerate_pub_key") return Operation::RegeneratePubKey;
    return Operation::None;
}

extern "C" {

int run_crypto_op_json(const char* json_config_str) {
    nlohmann::json json_config;
    try {
        json_config = nlohmann::json::parse(json_config_str);
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        return 1; // JSONパースエラー
    }

    CryptoConfig config;
    try {
        // Operation
        if (json_config.contains("operation")) {
            config.operation = get_operation_from_string(json_config["operation"].get<std::string>());
        }
        // Mode
        if (json_config.contains("mode")) {
            config.mode = get_mode_from_string(json_config["mode"].get<std::string>());
        }
        // Paths
        if (json_config.contains("input_files")) {
            config.input_files = json_config["input_files"].get<std::vector<std::string>>();
        }
        if (json_config.contains("output_file")) {
            config.output_file = json_config["output_file"].get<std::string>();
        }
        if (json_config.contains("input_dir")) {
            config.input_dir = json_config["input_dir"].get<std::string>();
        }
        if (json_config.contains("output_dir")) {
            config.output_dir = json_config["output_dir"].get<std::string>();
        }
        if (json_config.contains("key_dir")) {
            config.key_dir = json_config["key_dir"].get<std::string>();
        }
        if (json_config.contains("signature_file")) {
            config.signature_file = json_config["signature_file"].get<std::string>();
        }
        // Key paths - nlohmann::jsonのobjectをstd::mapに変換
        // 例: "key_paths": { "recipient_pubkey": "public_enc_pqc.key", "user_privkey": "private_enc_pqc.key" }
        if (json_config.contains("key_paths") && json_config["key_paths"].is_object()) {
            for (auto& [key, value] : json_config["key_paths"].items()) {
                if (value.is_string()) {
                    config.key_paths[key] = value.get<std::string>();
                } else {
                    std::cerr << "Warning: key_paths entry '" << key << "' is not a string. Skipping." << std::endl;
                }
            }
        } else if (json_config.contains("recipient_pubkey")) { // 後方互換性のため
            config.key_paths["recipient_pubkey"] = json_config["recipient_pubkey"].get<std::string>();
        } else if (json_config.contains("user_privkey")) { // 後方互換性のため
            config.key_paths["user_privkey"] = json_config["user_privkey"].get<std::string>();
        }


        // Options
        if (json_config.contains("passphrase")) {
            config.passphrase = json_config["passphrase"].get<std::string>();
            config.passphrase_was_provided = true;
        }
        if (json_config.contains("digest_algo")) {
            config.digest_algo = json_config["digest_algo"].get<std::string>();
        }
        if (json_config.contains("sync_mode")) {
            config.sync_mode = json_config["sync_mode"].get<bool>();
        }
        if (json_config.contains("is_recursive")) {
            config.is_recursive = json_config["is_recursive"].get<bool>();
        }
        // For regenerate-pubkey
        if (json_config.contains("regenerate_privkey_path")) {
            config.regenerate_privkey_path = json_config["regenerate_privkey_path"].get<std::string>();
        }
        if (json_config.contains("regenerate_pubkey_path")) {
            config.regenerate_pubkey_path = json_config["regenerate_pubkey_path"].get<std::string>();
        }

    } catch (const nlohmann::json::exception& e) {
        std::cerr << "JSON mapping error: " << e.what() << std::endl;
        return 2; // JSONデータからCryptoConfigへのマッピングエラー
    } catch (const std::invalid_argument& e) {
        std::cerr << "Configuration error: " << e.what() << std::endl;
        return 3; // 不正な引数による構成エラー (例: 無効な暗号モード)
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred during configuration mapping: " << e.what() << std::endl;
        return 2;
    }

    try {
        // CryptoProcessorは自身のio_contextを内部で管理し、run()が非同期操作を開始する。
        // nkCryptoToolMain.cppと同様に、io_contextはここで直接渡さない。
        CryptoProcessor processor(config);
        auto future = processor.run(); // このメソッドは新しいスレッドをデタッチして操作を実行する
        future.get(); // デタッチされたスレッドの完了を待機する
        return 0; // 成功
    } catch (const std::exception& e) {
        std::cerr << "CryptoProcessor execution error: " << e.what() << std::endl;
        return 4; // CryptoProcessor実行エラー
    }
}

} // extern "C"
