#ifndef NKCRYPTO_FFI_HPP
#define NKCRYPTO_FFI_HPP

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief JSON設定文字列に基づいて暗号操作を実行します。
 *
 * @param json_config_str 暗号操作の設定を含むJSON文字列。
 *                        例:
 *                        {
 *                          "operation": "encrypt",
 *                          "mode": "pqc",
 *                          "input_files": ["file1.txt", "file2.txt"],
 *                          "output_file": "output.enc",
 *                          "key_dir": "./keys",
 *                          "recipient_pubkey": "public_enc_pqc.key",
 *                          "passphrase": "mysecretpassword",
 *                          "sync_mode": true
 *                        }
 * @return 0 成功。非ゼロ: エラーコード。
 *         1: JSONパースエラー
 *         2: JSONデータからCryptoConfigへのマッピングエラー
 *         3: 不正な引数による構成エラー (例: 無効な暗号モード)
 *         4: CryptoProcessor実行エラー
 */
int run_crypto_op_json(const char* json_config_str);

#ifdef __cplusplus
}
#endif

#endif // NKCRYPTO_FFI_HPP
