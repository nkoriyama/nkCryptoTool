#!/bin/bash

# --- デモを開始します (パスフレーズ入力あり) ---
echo "--- デモを開始します (パスフレーズ入力あり) ---"
echo

# 秘密鍵保存ディレクトリのパスを設定
KEY_DIR="$HOME/.nkencdec"
ENC_PRIVATE_KEY="$KEY_DIR/private_enc_ecc.key"
SIGN_PRIVATE_KEY="$KEY_DIR/private_sign_ecc.key"

# 秘密鍵保存ディレクトリが存在するか確認し、存在しない場合は作成
if [ ! -d "$KEY_DIR" ]; then
  echo "秘密鍵保存ディレクトリを作成します: $KEY_DIR"
  mkdir -p "$KEY_DIR"
  if [ $? -ne 0 ]; then
    echo "エラー: 秘密鍵保存ディレクトリの作成に失敗しました。"
    exit 1
  fi
  # ディレクトリのパーミッションを所有者のみに設定 (rwx)
  chmod 700 "$KEY_DIR"
  if [ $? -ne 0 ]; then
    echo "警告: 秘密鍵保存ディレクトリのパーミッション設定に失敗しました。"
  fi
fi

# --- 暗号化鍵ペアを生成します (パスフレーズ入力あり) ---
echo "--- 暗号化鍵ペアを生成します (パスフレーズ入力あり) ---"
# --no-passphrase オプションを削除し、パスフレーズ入力を必須とします。
# C++プログラムがインタラクティブにパスフレーズを要求します。
./nkencdec_ECC --gen-enc-key demo_enc.pub
if [ $? -ne 0 ]; then
  echo "エラー: 暗号化鍵ペアの生成に失敗しました。"
  exit 1
fi
echo

# --- 署名鍵ペアを生成します (パスフレーズ入力あり) ---
echo "--- 署名鍵ペアを生成します (パスフレーズ入力あり) ---"
# --no-passphrase オプションを削除し、パスフレーズ入力を必須とします。
# C++プログラムがインタラクティブにパスフレーズを要求します。
./nkencdec_ECC --gen-signing-key demo_sign.pub
if [ $? -ne 0 ]; then
  echo "エラー: 署名鍵ペアの生成に失敗しました。"
  exit 1
fi
echo

# 秘密鍵ファイルのパーミッションを所有者のみに設定 (rw)
if [ -f "$ENC_PRIVATE_KEY" ]; then
  chmod 600 "$ENC_PRIVATE_KEY"
  if [ $? -ne 0 ]; then
    echo "警告: 暗号化秘密鍵ファイルのパーミッション設定に失敗しました。"
  fi
fi
if [ -f "$SIGN_PRIVATE_KEY" ]; then
  chmod 600 "$SIGN_PRIVATE_KEY"
  if [ $? -ne 0 ]; then
    echo "警告: 署名秘密鍵ファイルのパーミッション設定に失敗しました。"
  fi
fi

# --- テスト用の入力ファイルを作成します ---
echo "--- テスト用の入力ファイルを作成します ---"
echo "This is a test file for encryption and signing demo." >demo_input.txt
echo "This line will be encrypted and signed." >>demo_input.txt
echo

# --- ファイルを暗号化します (demo_input.txt to demo_encrypted.bin using demo_enc.pub) ---
echo "--- ファイルを暗号化します (demo_input.txt to demo_encrypted.bin using demo_enc.pub) ---"
# 暗号化には受信者の公開鍵のみが必要で、秘密鍵のパスフレーズは不要です。
./nkencdec_ECC -e demo_input.txt -o demo_encrypted.bin -r demo_enc.pub
if [ $? -ne 0 ]; then
  echo "エラー: ファイルの暗号化に失敗しました。"
  exit 1
fi
echo

# --- ファイルを復号化します (demo_encrypted.bin to demo_decrypted.txt using default encryption private key) ---
echo "--- ファイルを復号化します (demo_encrypted.bin to demo_decrypted.txt using default encryption private key) ---"
echo
# 復号化には秘密鍵のパスフレーズ入力が必要です。
# C++プログラムがインタラクティブにパスフレーズを要求します。
./nkencdec_ECC -d demo_encrypted.bin -o demo_decrypted.txt
if [ $? -ne 0 ]; then
  echo "エラー: ファイルの復号化に失敗しました。"
  exit 1
fi
echo

# --- ファイルを署名します (demo_input.txt to demo_signature.sig using default signing private key) ---
echo "--- ファイルを署名します (demo_input.txt to demo_signature.sig using default signing private key) ---"
echo
# 署名には秘密鍵のパスフレーズ入力が必要です。
# C++プログラムがインタラクティブにパスフレーズを要求します。
./nkencdec_ECC -s demo_input.txt -o demo_signature.sig
if [ $? -ne 0 ]; then
  echo "エラー: ファイルの署名に失敗しました。"
  exit 1
fi
echo

# --- 署名を検証します (demo_input.txt, demo_signature.sig using demo_sign.pub) ---
echo "--- 署名を検証します (demo_input.txt, demo_signature.sig using demo_sign.pub) ---"
# 署名検証には署名者の公開鍵のみが必要で、秘密鍵のパスフレーズは不要です。
./nkencdec_ECC -v demo_input.txt --signature demo_signature.sig --signing-pubkey demo_sign.pub
if [ $? -ne 0 ]; then
  echo "エラー: 署名の検証に失敗しました。"
  exit 1
fi
echo

# --- デモが完了しました (パスフレーズ入力あり) ---
echo "--- デモが完了しました (パスフレーズ入力あり) ---"
echo

echo "生成されたファイル: demo_enc.pub, demo_sign.pub, demo_input.txt, demo_encrypted.bin, demo_decrypted.txt, demo_signature.sig"
echo "デフォルトの秘密鍵は以下の場所に保存されています:"
echo "  暗号化: $ENC_PRIVATE_KEY"
echo "  署名:   $SIGN_PRIVATE_KEY"

# 終了前に一時停止
read -p "続行するには何かキーを押してください..."

exit 0
