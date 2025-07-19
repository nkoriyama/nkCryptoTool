# nkCryptoTool 操作ガイド

このツールで何をしたいですか？以下の選択肢から、実行したい操作を選んでください。

## 目次
*   [1. 鍵の作成](#1-鍵の作成)
*   [2. 公開鍵の再生成](#2-公開鍵の再生成)
*   [3. 暗号化](#3-暗号化)
*   [4. 復号](#4-復号)
*   [5. デジタル署名](#5-デジタル署名)
*   [6. 検証](#6-検証)

---

## 1. 鍵の作成

**目的**: 暗号化やデジタル署名に使用する公開鍵と秘密鍵のペアを生成します。

**必要なもの**:

*   生成する鍵の種類（暗号化用か署名用か）。
*   鍵を保存するディレクトリ（指定しない場合は `./keys` に保存されます）。
*   秘密鍵を保護するためのパスフレーズ（任意）。

**コマンド例**:

*   **ECC暗号化鍵ペアの生成**:
    ```bash
    nkCryptoTool --mode ecc --gen-enc-key
    ```
*   **PQC署名鍵ペアの生成**:
    ```bash
    nkCryptoTool --mode pqc --gen-sign-key
    ```
*   **ハイブリッド暗号化鍵ペアの生成 (ML-KEM + ECDH)**:
    ```bash
    nkCryptoTool --mode hybrid --gen-enc-key
    ```
    *補足*: このコマンドを実行すると、ML-KEMとECDHの両方の鍵が生成されます。
*   **パスフレーズ付きで鍵を生成**:
    ```bash
    nkCryptoTool --mode ecc --gen-enc-key --passphrase "あなたの安全なパスフレーズ"
    ```
    *補足*: パスフレーズをコマンドラインで直接指定すると、コマンド履歴に残る可能性があります。安全のためには、`--passphrase` オプションを省略し、プロンプトが表示された際に入力することをお勧めします。

---

## 2. 公開鍵の再生成

**目的**: 既存の秘密鍵から公開鍵を再生成し、ファイルに保存します。これは、公開鍵を紛失した場合や、異なる形式で公開鍵をエクスポートしたい場合に便利です。

**必要なもの**:

*   公開鍵を再生成したい秘密鍵ファイル。
*   再生成された公開鍵を保存するファイル名。
*   秘密鍵にパスフレーズが設定されている場合、そのパスフレーズ。

**コマンド例**:

*   **秘密鍵から公開鍵を再生成**:
    ```bash
    nkCryptoTool --regenerate-pubkey "秘密鍵.key" "再生成された公開鍵.pub"
    ```
    *補足*: 秘密鍵のパスフレーズは、コマンド実行時にプロンプトで求められます。

---

## 3. 暗号化

**目的**: ファイルの内容を暗号化し、指定した公開鍵の所有者のみが復号できるようにします。

**必要なもの**:

*   暗号化したい入力ファイル。
*   暗号化されたデータを出力するファイル名。
*   受信者の公開鍵ファイル。
    *   **ECCモード**: 受信者のECC公開鍵。
    *   **PQCモード**: 受信者のML-KEM公開鍵。
    *   **ハイブリッドモード**: 受信者のML-KEM公開鍵とECDH公開鍵の両方。

**コマンド例**:

*   **ECCでファイルを暗号化**:
    ```bash
    nkCryptoTool --mode ecc --encrypt --input "元のファイル.txt" --output "暗号化されたファイル.ecc" --recipient-pubkey "受信者のECC公開鍵.key"
    ```
*   **PQCでファイルを暗号化**:
    ```bash
    nkCryptoTool --mode pqc --encrypt --input "元のファイル.txt" --output "暗号化されたファイル.pqc" --recipient-pubkey "受信者のML-KEM公開鍵.key"
    ```
*   **ハイブリッドモードでファイルを暗号化**:
    ```bash
    nkCryptoTool --mode hybrid --encrypt --input "元のファイル.txt" --output "暗号化されたファイル.hybrid" --recipient-mlkem-pubkey "受信者のML-KEM公開鍵.key" --recipient-ecdh-pubkey "受信者のECDH公開鍵.key"
    ```

---

## 4. 復号

**目的**: 暗号化されたファイルを復号し、元のファイルの内容に戻します。

**必要なもの**:

*   復号したい暗号化された入力ファイル。
*   復号されたデータを出力するファイル名。
*   自身の秘密鍵ファイル。
    *   **ECCモード**: 自身のECC秘密鍵。
    *   **PQCモード**: 自身のML-KEM秘密鍵。
    *   **ハイブリッドモード**: 自身のML-KEM秘密鍵とECDH秘密鍵の両方。
*   秘密鍵にパスフレーズが設定されている場合、そのパスフレーズ。

**コマンド例**:

*   **ECCでファイルを復号**:
    ```bash
    nkCryptoTool --mode ecc --decrypt --input "暗号化されたファイル.ecc" --output "復号されたファイル.txt" --user-privkey "自身のECC秘密鍵.key"
    ```
*   **PQCでファイルを復号**:
    ```bash
    nkCryptoTool --mode pqc --decrypt --input "暗号化されたファイル.pqc" --output "復号されたファイル.txt" --user-privkey "自身のML-KEM秘密鍵.key"
    ```
*   **ハイブリッドモードでファイルを復号**:
    ```bash
    nkCryptoTool --mode hybrid --decrypt --input "暗号化されたファイル.hybrid" --output "復号されたファイル.txt" --recipient-mlkem-privkey "自身のML-KEM秘密鍵.key" --recipient-ecdh-privkey "自身のECDH秘密鍵.key"
    ```
    *補足*: 秘密鍵のパスフレーズは、コマンド実行時にプロンプトで求められます。

---

## 5. デジタル署名

**目的**: ファイルの内容が改ざんされていないことを証明するために、デジタル署名を生成します。

**必要なもの**:

*   署名したい入力ファイル。
*   生成された署名を出力するファイル名。
*   自身の署名用秘密鍵ファイル。
*   秘密鍵にパスフレーズが設定されている場合、そのパスフレーズ。
*   使用するハッシュアルゴリズム（デフォルトはSHA256）。

**コマンド例**:

*   **ECCでファイルを署名**:
    ```bash
    nkCryptoTool --mode ecc --sign --input "文書.txt" --signature "文書.sig" --signing-privkey "自身のECC署名秘密鍵.key" --digest-algo SHA256
    ```
*   **PQCでファイルを署名**:
    ```bash
    nkCryptoTool --mode pqc --sign --input "文書.txt" --signature "文書.sig" --signing-privkey "自身のPQC署名秘密鍵.key"
    ```
    *補足*: PQC署名（ML-DSA）の場合、通常は内部でハッシュ処理を行うため、`--digest-algo` の指定は不要です。

---

## 6. 検証

**目的**: デジタル署名が正当なものであり、署名されたファイルが改ざんされていないことを確認します。

**必要なもの**:

*   署名が検証したい入力ファイル（元のファイル）。
*   署名ファイル。
*   署名者の公開鍵ファイル。
*   使用されたハッシュアルゴリズム（署名時と同じものを指定）。

**コマンド例**:

*   **ECC署名を検証**:
    ```bash
    nkCryptoTool --mode ecc --verify --input "文書.txt" --signature "文書.sig" --signing-pubkey "署名者のECC署名公開鍵.key" --digest-algo SHA256
    ```
*   **PQC署名を検証**:
    ```bash
    nkCryptoTool --mode pqc --verify --input "文書.txt" --signature "文書.sig" --signing-pubkey "署名者のPQC署名公開鍵.key"
    ```
    *補足*: 検証が成功すると「Signature verified successfully.」、失敗すると「Signature verification failed.」と表示されます。