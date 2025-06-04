@echo off
REM --- デモを開始します (パスフレーズ入力あり) ---
echo --- デモを開始します (パスフレーズ入力あり) ---
echo.

REM %USERPROFILE%\AppData\.nkencdec ディレクトリが存在するか確認し、存在しない場合は作成
if not exist "%USERPROFILE%\AppData\.nkencdec" (
    echo 秘密鍵保存ディレクトリを作成します: %USERPROFILE%\AppData\.nkencdec
    mkdir "%USERPROFILE%\AppData\.nkencdec"
    if errorlevel 1 (
        echo エラー: 秘密鍵保存ディレクトリの作成に失敗しました。
        goto end
    )
)

REM --- 暗号化鍵ペアを生成します (パスフレーズ入力あり) ---
echo --- 暗号化鍵ペアを生成します (パスフレーズ入力あり) ---
REM --no-passphrase オプションを削除し、パスフレーズ入力を必須とします。
.\build\bin\nkEncDec --mode=ecc --gen-enc-key demo_enc.pub
if errorlevel 1 (
    echo エラー: 暗号化鍵ペアの生成に失敗しました。
    goto end
)
echo.

REM --- 署名鍵ペアを生成します (パスフレーズ入力あり) ---
echo --- 署名鍵ペアを生成します (パスフレーズ入力あり) ---
REM --no-passphrase オプションを削除し、パスフレーズ入力を必須とします。
.\build\bin\nkEncDec --mode=ecc --gen-signing-key demo_sign.pub
if errorlevel 1 (
    echo エラー: 署名鍵ペアの生成に失敗しました。
    goto end
)
echo.

REM --- テスト用の入力ファイルを作成します ---
echo --- テスト用の入力ファイルを作成します ---
echo This is a test file for encryption and signing demo. > demo_input.txt
echo This line will be encrypted and signed. >> demo_input.txt
echo.

REM --- ファイルを暗号化します (demo_input.txt to demo_encrypted.bin using demo_enc.pub) ---
echo --- ファイルを暗号化します (demo_input.txt to demo_encrypted.bin using demo_enc.pub) ---
REM 暗号化には受信者の公開鍵のみが必要で、秘密鍵のパスフレーズは不要です。
.\build\bin\nkEncDec --mode=ecc -e demo_input.txt -o demo_encrypted.bin -r demo_enc.pub
if errorlevel 1 (
    echo エラー: ファイルの暗号化に失敗しました。
    goto end
)
echo.

REM --- ファイルを復号化します (demo_encrypted.bin to demo_decrypted.txt using default encryption private key) ---
echo --- ファイルを復号化します (demo_encrypted.bin to demo_decrypted.txt using default encryption private key) ---
echo.
REM 復号化には秘密鍵のパスフレーズ入力が必要です。
.\build\bin\nkEncDec --mode=ecc -d demo_encrypted.bin -o demo_decrypted.txt
if errorlevel 1 (
    echo エラー: ファイルの復号化に失敗しました。
    goto end
)
echo.

REM --- ファイルを署名します (demo_input.txt to demo_signature.sig using default signing private key) ---
echo --- ファイルを署名します (demo_input.txt to demo_signature.sig using default signing private key) ---
echo.
REM 署名には秘密鍵のパスフレーズ入力が必要です。
.\build\bin\nkEncDec --mode=ecc -s demo_input.txt -o demo_signature.sig
if errorlevel 1 (
    echo エラー: ファイルの署名に失敗しました。
    goto end
)
echo.

REM --- 署名を検証します (demo_input.txt, demo_signature.sig using demo_sign.pub) ---
echo --- 署名を検証します (demo_input.txt, demo_signature.sig using demo_sign.pub) ---
REM 署名検証には署名者の公開鍵のみが必要で、秘密鍵のパスフレーズは不要です。
.\build\bin\nkEncDec --mode=ecc  -v demo_input.txt --signature demo_signature.sig --signing-pubkey demo_sign.pub
if errorlevel 1 (
    echo エラー: 署名の検証に失敗しました。
    goto end
)
echo.

REM --- デモが完了しました (パスフレーズ入力あり) ---
echo --- デモが完了しました (パスフレーズ入力あり) ---
echo.

echo 生成されたファイル: demo_enc.pub, demo_sign.pub, demo_input.txt, demo_encrypted.bin, demo_decrypted.txt, demo_signature.sig
echo デフォルトの秘密鍵は以下の場所に保存されています:
echo   暗号化: %%USERPROFILE%%\AppData\.nkencdec\private_enc_ecc.key (Windows) または ~/.nkencdec/private_enc_ecc.key (Unix-like)
echo   署名:   %%USERPROFILE%%\AppData\.nkencdec\private_sign_ecc.key (Windows) または ~/.nkencdec/private_sign_ecc.key (Unix-like)

:end
echo.
pause
