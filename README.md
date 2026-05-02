# **nkCryptoTool**

**nkCryptoToolは、次世代暗号技術を含む高度な暗号処理をコマンドラインで手軽にセキュアに実行できるツールです。**

> **🚧 現在開発中（Alpha段階）**  
> CLIのみ対応です。本格的な利用はまだおすすめしていません。  
> C++版とRust版で完全な相互互換性があります。

**nkCryptoToolは、次世代暗号技術を含む高度な暗号処理をコマンドラインで手軽にセキュアに実行できるツールです。**

**初めてお使いの方や、暗号技術に詳しくない方は、まずこちらの [GETTING_STARTED.md](GETTING_STARTED.md) をご覧ください。**

* **データの暗号化・復号**: 秘密の情報を安全にやり取りできます。
* **柔軟な認証付き暗号 (AEAD) の選択**: 
    * **AES-256-GCM (デフォルト)**: ハードウェア加速（AES-NI等）が利用可能な環境で最高のパフォーマンスを発揮します。
    * **ChaCha20-Poly1305**: ハードウェア支援がない低電力デバイスや古いCPU環境において、AESを上回る高速なソフトウェア処理が可能です。
    * 実行時に `--aead-algo` オプションで動的に切り替え可能。
* **デジタル署名・検証**: ファイルの改ざんを検出し、作成者を証明できます。  
* **ECC (楕円曲線暗号)** および **PQC (耐量子計算機暗号)**、さらにRFC 9180の設計思想に基づきPQC (ML-KEM)とECC (ECDH)を組み合わせた**ハイブリッド暗号**に対応。  
* **TPM (Trusted Platform Module) による秘密鍵の保護**: 秘密鍵をマシンのハードウェア (TPM) に紐付けて安全にラッピング保存できます。原本（生鍵）からの再ラッピングやアンラップにも対応し、究極のセキュリティとポータビリティを両立しています。
* **安定したストリーミング処理**: Asioライブラリの非同期I/Oとパイプライン設計により、5GB以上の巨大なファイルも **3GiB/s を超える圧倒的な高速スループット**で安定して暗号化・復号できます。 (PQCの署名・検証はML-DSAの仕様制限により一括処理)
* **マルチバックエンド対応**: OpenSSL に加え、wolfSSL、さらに Rust 版では RustCrypto をバックエンドとして選択可能。異なるバックエンド間で 100% のバイナリ相互運用性を実現しており、OpenSSL版で暗号化したファイルをwolfSSL版で復号するといった運用が可能です。

## **セキュリティ (Security)**

本プロジェクトは、強力なセキュリティ保証を念頭に設計されています。

### **ファイルフォーマットと互換性**
* **ヘッダーバージョン 2**: 最新バージョンでは、使用した AEAD アルゴリズム情報をヘッダーに含めることで動的なアルゴリズムの切り替えをサポートしています。
* **後方互換性 (Backward Compatibility)**: 以前のバージョン (v1) で暗号化された AES-256-GCM 固定のファイルも、最新のツールで自動的に識別し、そのまま復号可能です。

#### **バイナリレイアウト (.nkct / 暗号化ファイル)**

```mermaid
packet-beta
0-31: "Magic (NKCT)"
32-47: "Version (2)"
48-55: "Strategy Type (1:ECC / 2:PQC / 3:Hybrid)"
56-119: "Strategy Data (Variable Length ...)"
```

**Strategy Data の構成 (Version 2):**
*   **ECC**: `CurveName`, `DigestAlgo`, `EphemeralPubKey`, `Salt`, `IV`, `AEADAlgo`
*   **PQC**: `KEMAlgo`, `DSAAlgo`, `KEM-CT`, `Salt`, `IV`, `AEADAlgo`
*   **Hybrid**: `ECCHeaderLength`, `ECCHeader`, `PQCHeaderLength`, `PQCHeader` (Hybrid自体の外枠バージョンは1)

#### **バイナリレイアウト (.nkcs / 署名ファイル)**

```mermaid
packet-beta
0-31: "Magic (NKCS)"
32-47: "Version (1)"
48-55: "Strategy Type (1:ECC / 2:PQC / 3:Hybrid)"
56-119: "Signature Data (Variable Length ...)"
```

※ 文字列やバイナリ配列は、`[4バイトの長さ(uint32_t)][実データ]` の形式で連続して格納されます。数値はすべてリトルエンディアンです。

以下の詳細については [SECURITY.md](./SECURITY.md) を参照してください。
- 鍵のライフサイクル設計
- メモリ保護モデル
- 脅威モデルと制限事項

## **はじめに (How to Get Started)**

このツールは、暗号技術の知識を持つ開発者向けに設計されています。

1. **ビルド**: [ビルド方法](#ビルド方法) セクションを参照し、OpenSSL などの依存ライブラリをセットアップしてプログラムをビルドします。  
2. **使用**: [使用法](#使用法) セクションで、各機能のコマンドラインオプションと具体的な実行例を確認できます。

**暗号初心者の方や、まずは簡単に試してみたい方は、[GETTING_STARTED.md](GETTING_STARTED.md) をご覧ください。**

## **詳細情報 (More Information)**

*   **高速化の秘訣**: 本ツールのパフォーマンス最適化に関する詳細な情報は、[nkCryptoTool_optimization_secrets.md](nkCryptoTool_optimization_secrets.md) をご覧ください。
*   **ベンチマーク実績**: 2.0 GiB の大容量ファイルを用いた最新のベンチマーク結果（Gen4 NVMe / x86_64 / Linux）。

| バックエンド (言語) | モード | 暗号化速度 | 復号速度 |
| :--- | :--- | :--- | :--- |
| **OpenSSL (Rust)** | **Hybrid (PQC+ECC)** | **~3.7 GiB/s** | **~3.8 GiB/s** |
| **OpenSSL (Rust)** | PQC (ML-KEM-1024) | ~3.7 GiB/s | ~3.8 GiB/s |
| **OpenSSL (Rust)** | ECC (P-256) | ~3.5 GiB/s | ~3.8 GiB/s |
| OpenSSL (C++) | Hybrid (PQC+ECC) | ~2.7 GiB/s | ~2.8 GiB/s |
| OpenSSL (C++) | PQC (ML-KEM-1024) | ~3.0 GiB/s | ~3.1 GiB/s |
| OpenSSL (C++) | ECC (P-256) | ~2.7 GiB/s | ~2.8 GiB/s |
| wolfSSL (C++) | Hybrid (PQC+ECC) | ~2.1 GiB/s | ~2.1 GiB/s |
| wolfSSL (C++) | PQC (ML-KEM-1024) | ~1.9 GiB/s | ~1.9 GiB/s |
| wolfSSL (C++) | ECC (P-256) | ~1.9 GiB/s | ~1.9 GiB/s |
| **RustCrypto (Rust)** | **Hybrid (PQC+ECC)** | **~1.6 GiB/s** | **~1.7 GiB/s** |
| **RustCrypto (Rust)** | PQC (ML-KEM-1024) | ~1.5 GiB/s | ~1.7 GiB/s |
| **RustCrypto (Rust)** | ECC (P-256) | ~1.7 GiB/s | ~1.7 GiB/s |

※ Rust 版は Tokio 非同期パイプラインにより I/O と暗号化を高度に並列化しており、特に巨大ファイルにおいて C++ 版を上回る効率を発揮します。詳細は [nkCryptoToolBenchmark](#ベンチマーク) を実行してご確認ください。

## **ビルド方法**

### **本プロジェクトは CMakeとNinjaを使用してビルドされます**

**依存関係:**

* **C++23対応コンパイラ**: (例: GCC 13+, Clang 16+, MSVC 2022+)  
* **CMake**: 3.11以上  
* **Ninja**: (推奨ビルドシステム)  
* **OpenSSL**: 3.0 以降  
  * **PQC機能を使用する場合**: OpenSSL 3.5 以降を推奨します。(標準PQCアルゴリズムをサポートしているため)
  * **TPM機能を使用する場合**: `tpm2-openssl` プロバイダがインストールされ、OpenSSLから利用可能である必要があります。

**ビルド手順:**

1. **依存ライブラリのインストール:**  
   * **Ubuntu/Debian:**  
     sudo apt update && sudo apt install build-essential cmake ninja-build libssl-dev

   * **macOS (Homebrew):**  
     brew install openssl@3 cmake ninja

   * **Windows (MSYS2/MinGW):**  
     pacman \-S mingw-w64-x86\_64-toolchain mingw-w64-x86\_64-cmake mingw-w64-x86\_64-ninja mingw-w64-x86\_64-openssl

2. **リポジトリのクローン:**  
   git clone https://github.com/n-koriyama/nkCryptoTool.git  
   cd nkCryptoTool

3. **ビルドの実行:**  
   ビルド時に `-DUSE_BACKEND` フラグを指定することで、暗号バックエンドを切り替えられます。

   *   **OpenSSL版 (デフォルト):**
       ```bash
       cmake -B build -G "Ninja" -DUSE_BACKEND=OpenSSL
       cmake --build build
       ```
   *   **wolfSSL版:**
       ```bash
       cmake -B build_wolfssl -G "Ninja" -DUSE_BACKEND=WolfSSL
       cmake --build build_wolfssl
       ```

   *ビルドが成功すると、実行可能ファイルが各ビルドディレクトリの直下に生成されます。*

## **ベンチマーク**
`nkCryptoToolBenchmark`は、暗号化・復号、署名・検証のパフォーマンスを測定するための独立したベンチマークプログラムです。1KBから**最大5GB**までのデータサイズに対応しており、マシンの限界性能を測定できます。

    build/bin/nkCryptoToolBenchmark

## **TPM による秘密鍵の保護**

本ツールは、TPM (Trusted Platform Module) を使用して秘密鍵を安全にラッピング（暗号化）して保存する機能を備えています。

### **特徴**
* **TPM 2.0 HMACセッションの採用**: パスワードをTPMに直接送るのではなく、HMACセッションによるセキュアな通信路を確立して認証を行います。これにより、マザーボード上のバス盗聴やリプレイ攻撃から保護されます。
* **独自ラッピング方式**: ECCおよびPQCの秘密鍵を `-----BEGIN TPM WRAPPED BLOB-----` という独自ヘッダーを持つ形式で保存します。
* **ポータビリティの確保**: 秘密鍵をTPM内部で生成するのではなく、ソフトウェアで生成した鍵をTPMでシールドする方式を採用しています。これにより、原本（生鍵）を安全に保管しておけば、故障時や他環境への移行時に再ラッピングが可能です。
* **シェル排除による安全性**: コマンド実行に `system()` や `/bin/sh` を一切使用せず、`posix_spawn` による直接プロセス起動を行うことで、OSコマンドインジェクションを物理的に遮断しています。

## **鍵管理アーキテクチャ**

```mermaid
flowchart TD
    User --> CryptoProcessor
    CryptoProcessor --> Strategy

    Strategy --> ECC
    Strategy --> PQC
    Strategy --> Hybrid

    Strategy --> KeyProvider
    KeyProvider -->|unwrap key| TPM
```

- **KeyProvider による抽象化**: 暗号操作を鍵ストレージの実装から分離。メインロジックは具体的な保護メカニズム（TPM等）に依存しません。
- **セキュアな TPM バックエンド**: TPM 2.0 HMAC セッションと安全なプロセス実行（シェル排除）を活用し、堅牢なハードウェアベースの鍵ラッピングを提供します。
- **高い拡張性**: 将来的に Cloud KMS、ハードウェアセキュリティモジュール (HSM)、あるいは高度なソフトウェアベースのプロバイダーへの拡張が可能な設計になっています。

### **プロセス終了時の鍵保護について**

プロセレベルの強制終了（SIGKILL、abort、OOM killer等）が発生した場合、RAIIベースのクリーンアップ（デストラクタによるメモリ消去）は実行されません。このようなシナリオにおける鍵情報の扱いは以下の通りです。

1. **OSレベルのメモリ隔離**
   現代的なOSは厳格なプロセス隔離を強制しています。終了したプロセスが使用していたメモリが、そのまま他のプロセスに公開されることはありません。メモリページは再割り当てされる前にカーネルによってクリアまたは初期化され、プロセス間でのデータ漏洩を防ぎます。
2. **コアダンプのリスク**
   コアダンプが有効な場合、異常終了時のメモリ内容がディスクに書き出されるリスクがあります。本ツールではこれを防ぐため、プログラム内で `setrlimit` を呼び出し、コアダンプの生成を明示的に無効化しています。
3. **物理メモリへの残留**
   急激な終了時には、鍵情報が一時的にRAM上に残留する可能性があります。しかし、`mlock` の使用により、スワップ（ディスクへの書き出し）経由で機密データがディスクに残ることはありません。なお、物理的なメモリ抽出攻撃（コールドブート攻撃など）は、ソフトウェアのみによる対策の範囲外としています。

**結論:**
強制終了下ではソフトウェアによる完全なゼロ上書き（Zeroization）は保証できませんが、本ツールの設計により以下の安全性が確保されます。
* 他のプロセスへの漏洩防止 (OSによる隔離)
* ディスクへの永続化防止 (`mlock` + コアダンプ制御)
* RAM上の露出時間の最小化

これは、ユーザー空間で動作する暗号化アプリケーションにおける実用的なセキュリティ境界を代表する設計となっています。

### **TPM関連の操作**

* **TPM保護された鍵ペアの生成**:  
  鍵生成コマンドに `--tpm` を追加します。  
  nkCryptoTool \--mode pqc \--tpm \--gen-enc-key \--key-dir ~/.keys
* **既存の生鍵をTPMでラッピングする**:  
  原本の生鍵を現在のマシンのTPMで保護します。  
  nkCryptoTool \--mode ecc \--tpm \--wrap-existing \<raw\_private\_key.key\>  
  (出力: `<鍵名>.tpmkey`)
* **TPM保護鍵を解除（アンラップ）する**:  
  TPM保護された鍵を標準的な秘密鍵に戻します（原本の取り出し）。  
  nkCryptoTool \--mode ecc \--tpm \--unwrap-key \<tpm\_wrapped\_key.key\>  
  (出力: `<鍵名>.rawkey`)

### **注意点 (Linux)**
Linux環境では、TPMデバイス（`/dev/tpmrm0` など）へのアクセス権限が必要です。通常、これらのデバイスは `tss` グループに属しているため、TPM機能を利用するには以下のいずれかが必要です。
* `sudo` による実行（root権限）
* 実行ユーザーを `tss` グループに追加 (`sudo usermod -aG tss $USER` を実行後、再ログイン)

## **鍵の互換性と標準フォーマット**

本ツールで生成される鍵ペアは、異なる実装（C++版/Rust版）や異なるバックエンド（OpenSSL/WolfSSL/RustCrypto）の間で、変換なしにそのまま相互利用可能です。

### **1. ECC (楕円曲線暗号)**
*   **構造**: NIST P-256 (prime256v1) 曲線を使用。
*   **形式**: 業界標準の **PEM (Privacy-Enhanced Mail)** 形式で保存。
    *   **秘密鍵**: PKCS#8 構造（TPM保護なしの場合）
    *   **公開鍵**: SubjectPublicKeyInfo (SPKI) 構造
*   これにより、`ssh-keygen` や `openssl` コマンド等、標準的なツールとの高い親和性を確保しています。

### **2. PQC (耐量子計算機暗号)**
*   **アルゴリズム**: NIST標準の ML-KEM (Kyber) および ML-DSA (Dilithium) を採用。
*   **ASN.1 構造**: 業界標準のデータ構造を共通採用しています。
    *   **公開鍵 (SubjectPublicKeyInfo)**:
        ```asn1
        SEQUENCE {
          algorithm        AlgorithmIdentifier, -- 種類 (OID: 2.16.840.1.101.3.4.4.2 等)
          subjectPublicKey BIT STRING           -- 生の公開鍵バイナリ
        }
        ```
    *   **秘密鍵 (PKCS#8 / OneAsymmetricKey)**:
        ```asn1
        SEQUENCE {
          version           INTEGER (0),
          privateKeyAlgorithm AlgorithmIdentifier,
          privateKey        OCTET STRING {
            SEQUENCE {
              seed          OCTET STRING,       -- 鍵生成シード (xi / d,z)
              rawKey        OCTET STRING        -- 生の秘密鍵バイナリ
            }
          }
        }
        ```
*   **OID (Object Identifier)**: 全実装で以下の標準/共通識別子を使用し、メタデータを識別します（出典: **NIST CSOR**, **FIPS 203/204**）。

        *   ML-KEM-768: `2.16.840.1.101.3.4.4.2` (id-alg-ml-kem-768)
        *   ML-DSA-65: `2.16.840.1.101.3.4.3.18` (id-ml-dsa-65)
    *   バイナリレベルで同一のラップ処理を行うため、Rust版で生成した PQC 鍵を C++版のバックエンドで直接読み込むことが可能です。

### **3. TPM 保護**
*   秘密鍵を TPM 2.0 で保護する場合、独自の **TPM Wrapped Blob** 形式（PEMラップ）を採用していますが、このパースロジックも C++/Rust 間で統一されています。

## **統一ヘッダーフォーマット (Unified Header Format)**

本ツールで暗号化されたファイル (`.nkct`) および署名ファイル (`.nkcs`) は、異なる言語（C++/Rust）やバックエンド（OpenSSL/wolfSSL/RustCrypto）間での完全な相互運用性を確保するため、以下の **Version 2 統一ヘッダー形式** を採用しています。

### **バイナリレイアウト (Version 2)**

```mermaid
packet-beta
0-31: "Magic (NKCT/NKCS)"
32-47: "Version (2)"
48-55: "Strategy Type (0/1/2)"
56-119: "Strategy Data (Variable Length ...)"
120-151: "AEAD Algorithm (String, Version 2+)"
```

すべての数値は**リトルエンディアン (Little-Endian)** で記録されます。

| オフセット | サイズ | 内容 | 説明 |
| :--- | :--- | :--- | :--- |
| 0 | 4 bytes | マジック | 暗号化: `NKCT`, 署名: `NKCS` |
| 4 | 2 bytes | バージョン | `2` (uint16_t) |
| 6 | 1 byte | 戦略タイプ | `0: ECC`, `1: PQC`, `2: Hybrid` |
| 7〜 | 可変 | ストラテジーデータ | アルゴリズム名、Salt、IV、KEM暗号文など |
| 可変 | 可変 | AEADアルゴリズム | 暗号化に使用したAEAD名（例: `AES-256-GCM`） |

※ **後方互換性**: バージョン `1` のファイル（AEAD名を含まない形式）を読み込む際は、自動的に `AES-256-GCM` と見なして処理されます。これにより、旧バージョンで暗号化されたデータも引き続き利用可能です。

※ 文字列やバイナリ配列は、`[4バイトの長さ(uint32_t)][実データ]` の形式で連続して格納されます。

## **使用法**

nkCryptoToolプログラムは、ECCモード (--mode ecc)、PQCモード (--mode pqc)、Hybridモード (--mode hybrid)の3つのモードで動作します。



### **鍵ペアの生成**

* 暗号化鍵ペア (ECC):  
  nkCryptoTool \--mode ecc \--gen-enc-key  
* 署名鍵ペア (ECC):  
  nkCryptoTool \--mode ecc \--gen-sign-key  
* 暗号化鍵ペア (PQC):  
  nkCryptoTool \--mode pqc \--gen-enc-key  
* 署名鍵ペア (PQC):  
  nkCryptoTool \--mode pqc \--gen-sign-key  
* 暗号化鍵ペア (Hybrid):  
  nkCryptoTool \--mode hybrid \--gen-enc-key
  これにより、ML-KEMとECDHの鍵ペアがそれぞれ生成されます (例: public_enc_hybrid_mlkem.key, private_enc_hybrid_mlkem.key, public_enc_hybrid_ecdh.key, private_enc_hybrid_ecdh.key)。
* 秘密鍵からの公開鍵の再生成:
  nkCryptoTool --regenerate-pubkey <private_key_path> <public_key_path>

**Note:** \--passphrase "" を付けるとパスフレーズなしで鍵を生成します。--key-dir \<path\> で鍵の保存先を指定できます。

### **暗号化**

* ECCモード:  
  nkCryptoTool \--mode ecc \--encrypt \--recipient-pubkey \<public\_key.key\> \-o \<encrypted.bin\> \<input.txt\>  
* PQCモード:  
  nkCryptoTool \--mode pqc \--encrypt \--recipient-pubkey \<public\_key.key\> \-o \<encrypted.bin\> \<input.txt\>  
* Hybridモード:  
  RFC 9180の設計思想に基づき、PQC (ML-KEM)とECC (ECDH)を組み合わせたハイブリッド暗号化を実行します。  
  nkCryptoTool \--mode hybrid \--encrypt \--recipient-mlkem-pubkey \<mlkem\_pub.key\> \--recipient-ecdh-pubkey \<ecdh\_pub.key\> \-o \<encrypted.bin\> \<input.txt\>
* **AEADアルゴリズムの指定**:  
  全てのモードで `--aead-algo <ALGO>` オプションを使用して暗号化アルゴリズムを指定できます。  
  指定例: `AES-256-GCM` (デフォルト), `ChaCha20-Poly1305`

### **復号**

* **全モード共通 (自動認識)**:  
  復号時、使用された AEAD アルゴリズムはファイルヘッダーから自動的に認識されます。ユーザーがアルゴリズムを明示的に指定する必要はありません。  
* ECCモード:  
  nkCryptoTool \--mode ecc \--decrypt \--user-privkey \<private\_key.key\> \-o \<decrypted.txt\> \<encrypted.bin\>  
* PQCモード:  
  nkCryptoTool \--mode pqc \--decrypt \--user-privkey \<private\_key.key\> \-o \<decrypted.txt\> \<encrypted.bin\>  
* TPM保護鍵を使用する場合:  
  上記のコマンドに `--tpm` フラグを追加してください。自動的にラッピングが解除されます。
* Hybridモード:  
  RFC 9180の設計思想に基づき、PQC (ML-KEM)とECC (ECDH)を組み合わせたハイブリッド暗号を復号します。  
  nkCryptoTool \--mode hybrid \--decrypt \--recipient-mlkem-privkey \<mlkem\_priv.key\> \--recipient-ecdh-privkey \<ecdh\_priv.key\> \-o \<decrypted.txt\> \<encrypted.bin\>

### **署名**

* ECCモード:  
  nkCryptoTool \--mode ecc \--sign \<input.txt\> \--signature \<file.sig\> \--signing-privkey \<private\_key.key\>  
* PQCモード:  
  nkCryptoTool \--mode pqc \--sign \<input.txt\> \--signature \<file.sig\> \--signing-privkey \<private\_key.key\>

**Note:** オプションで `--digest <algorithm>` を追加することで、署名に使われるハッシュアルゴリズムを指定できます (例: `SHA256`, `SHA3-512`)。指定しない場合のデフォルトは `SHA3-512` です。

### **署名検証**

* ECCモード:  
  nkCryptoTool \--mode ecc \--verify \<input.txt\> \--signature \<file.sig\> \--signing-pubkey \<public\_key.key\>  
* PQCモード:  
  nkCryptoTool \--mode pqc \--verify \<input.txt\> \--signature \<file.sig\> \--signing-pubkey \<public\_key.key\>



## **処理フロー**

### **鍵ペア生成シーケンスの比較**

#### **1. ECC モデル (標準)**
TPMを使用する場合でも、楕円曲線暗号（secp256k1など）を用いた標準的なフローです。

```mermaid
sequenceDiagram
    actor User
    participant nkcryptotool as nkcryptotool
    participant TPM as TPM (Hardware)
    participant FS as File System

    User->>nkcryptotool: ECC鍵生成コマンド (--mode ecc)
    nkcryptotool->>nkcryptotool: ソフトウェアでEC秘密鍵を生成
    alt TPM保護あり (--tpm)
        nkcryptotool->>TPM: 秘密鍵をインポート & シールド要求
        TPM-->>nkcryptotool: TPMラップ済みデータ (TSS2形式)
        nkcryptotool->>FS: -----BEGIN TPM WRAPPED PRIVATE KEY----- として保存
    else TPM保護なし
        nkcryptotool->>FS: 標準 PKCS#8 形式で保存
    end
    nkcryptotool-->>User: 完了通知
```

#### **2. PQC モデル (次世代・耐量子)**
TPMが直接サポートしていない ML-KEM 等の秘密鍵を、独自のラッピングロジックで保護する先進的なフローです。

```mermaid
sequenceDiagram
    actor User
    participant nkcryptotool as nkcryptotool
    participant TPM as TPM (Hardware)
    participant FS as File System

    User->>nkcryptotool: PQC鍵生成コマンド (--mode pqc)
    nkcryptotool->>nkcryptotool: ソフトウェアで ML-KEM 秘密鍵を生成
    alt TPM保護あり (--tpm)
        nkcryptotool->>TPM: 秘密鍵(DER)をシールド要求
        TPM-->>nkcryptotool: ハードウェア紐付け暗号化データ
        nkcryptotool->>FS: -----BEGIN TPM WRAPPED PRIVATE KEY----- として保存
    else TPM保護なし
        nkcryptotool->>FS: 標準 PKCS#8 形式で保存
    end
    nkcryptotool-->>User: 完了通知 (約4.4KBの巨大な秘密鍵を安全に保護)
```

#### **3. Hybrid モデル (最高機密・RFC 9180準拠)**
PQC と ECC の両方を同時に生成・管理する、最も複雑で堅牢なフローです。

```mermaid
sequenceDiagram
    actor User
    participant nkcryptotool as nkcryptotool
    participant TPM as TPM (Hardware)
    participant FS as File System

    User->>nkcryptotool: Hybrid鍵生成コマンド (--mode hybrid)
    par PQC鍵の生成
        nkcryptotool->>nkcryptotool: ML-KEM 鍵ペア生成
    and ECC鍵の生成
        nkcryptotool->>nkcryptotool: ECDH 鍵ペア生成
    end
    alt TPM保護あり (--tpm)
        nkcryptotool->>TPM: 両方の秘密鍵を個別にシールド
        TPM-->>nkcryptotool: それぞれのラップ済みデータ
        nkcryptotool->>FS: 2つの .tpmkey ファイルを出力
    else TPM保護なし
        nkcryptotool->>FS: 2つの標準 PKCS#8 ファイルを出力
    end
    nkcryptotool-->>User: 統合管理された鍵セットの生成完了
```

### **暗号化・復号シーケンスの技術モデル**

#### **1. ECC モデル (楕円曲線ディフィー・ヘルマン鍵共有)**
ECDH を用いて共通鍵を生成する、最も広く使われている標準的なフローです。

```mermaid
sequenceDiagram
    actor Sender
    actor Recipient
    participant FS as File System
    participant OS as OpenSSL

    Note over Sender, Recipient: 暗号化 (Sender)
    Sender->>FS: 受信者の公開鍵をロード
    Sender->>OS: エフェメラル鍵ペアを生成 & 受信者公開鍵と ECDH 実行
    OS-->>Sender: 共有秘密 (Shared Secret)
    Sender->>OS: HKDF で 共有秘密から AES鍵/IV を導出
    Sender->>FS: 暗号文 + エフェメラル公開鍵を出力

    Note over Sender, Recipient: 復号 (Recipient)
    Recipient->>FS: 自身の秘密鍵をロード (TPM/Passphrase保護)
    Recipient->>FS: ファイルからエフェメラル公開鍵をロード
    Recipient->>OS: 秘密鍵とエフェメラル公開鍵で ECDH 実行
    OS-->>Recipient: 共有秘密 (Senderと同じもの)
    Recipient->>OS: HKDF で AES鍵/IV を導出
    Recipient->>OS: AES-256-GCM でデータを復号
```

#### **2. PQC モデル (鍵カプセル化メカニズム - KEM)**
耐量子計算機暗号特有の **KEM (Key Encapsulation Mechanism)** 方式を採用した、次世代の暗号フローです。

```mermaid
sequenceDiagram
    actor Sender
    actor Recipient
    participant FS as File System
    participant OS as OpenSSL

    Note over Sender, Recipient: 暗号化 (Sender)
    Sender->>FS: 受信者の ML-KEM 公開鍵をロード
    Sender->>OS: Encapsulate (カプセル化) 実行
    OS-->>Sender: 共有秘密 & 暗号化された鍵 (Ciphertext)
    Sender->>OS: HKDF で AES鍵/IV を導出
    Sender->>FS: 暗号文 + KEM Ciphertext (約1.5KB) を出力

    Note over Sender, Recipient: 復号 (Recipient)
    Recipient->>FS: 自身の ML-KEM 秘密鍵をロード (TPMで保護)
    Recipient->>FS: ファイルから KEM Ciphertext をロード
    Recipient->>OS: Decapsulate (カプセル化解除) 実行
    OS-->>Recipient: 共有秘密 (Senderと同じもの)
    Recipient->>OS: HKDF で AES鍵/IV を導出
    Recipient->>OS: AES-256-GCM でデータを復号
```

#### **3. Hybrid モデル (RFC 9180 準拠・二重防壁)**
PQC (ML-KEM) と ECC (ECDH) を組み合わせ、**両方の暗号が同時に破られない限り安全**な、究極の機密性を実現するフローです。

```mermaid
sequenceDiagram
    actor Sender
    actor Recipient
    participant OS as OpenSSL

    Note over Sender, Recipient: 暗号化 (Sender)
    Sender->>OS: ML-KEM カプセル化実行 => 共有秘密 A
    Sender->>OS: ECDH 鍵共有実行 => 共有秘密 B
    Sender->>OS: 2つの共有秘密 (A + B) を連結
    Sender->>OS: HKDF (SHA3-256) で 1つの強力な AES鍵 を導出
    Sender-->>Recipient: 暗号文 + [KEM CT + EC PubKey] を送信

    Note over Sender, Recipient: 復号 (Recipient)
    Recipient->>OS: ML-KEM カプセル化解除 => 共有秘密 A
    Recipient->>OS: ECDH 鍵共有実行 => 共有秘密 B
    Recipient->>OS: A + B から同じ AES鍵 を導出
    Recipient->>OS: AES-256-GCM でデータを復号
    Note right of OS: 片方のアルゴリズムに脆弱性が見つかっても<br/>機密性は維持されます
```

### **デジタル署名シーケンス (Signer \-\> Verifier)**

```mermaid
sequenceDiagram
    actor Signer
    participant Signer_nkcryptotool as nkcryptotool (署名者側)
    participant FileSystem as ファイルシステム
    participant OpenSSL as OpenSSLライブラリ
    actor Verifier

    Signer->>Signer_nkcryptotool: 署名コマンド実行<br>(入力ファイル, 署名出力ファイル, 自身の署名秘密鍵ファイル, ダイジェストアルゴリズム)
    Signer_nkcryptotool->>User: パスフレーズ入力要求
    User->>Signer_nkcryptotool: パスフレーズ入力
    alt 秘密鍵読み込み成功
        Signer_nkcryptotool->>FileSystem: 自身の秘密鍵読み込み
        FileSystem-->>Signer_nkcryptotool: 署名秘密鍵データ<br>(復号済み)
        Signer_nkcryptotool->>FileSystem: 入力ファイル読み込み
        FileSystem-->>Signer_nkcryptotool: 入力ファイルデータ
        Signer_nkcryptotool->>OpenSSL: ファイルデータのハッシュ計算要求<br>(ダイジェストアルゴリズム)
        OpenSSL-->>Signer_nkcryptotool: ハッシュ値 (ダイジェスト)
        Signer_nkcryptotool->>OpenSSL: ダイジェストの署名要求<br>(ECC: ECDSA, PQC: ML-DSA)
        OpenSSL-->>Signer_nkcryptotool: 署名データ
        Signer_nkcryptotool->>FileSystem: 署名出力ファイル書き込み<br>(署名データ)
        FileSystem-->>Signer_nkcryptotool: 書き込み完了
        Signer_nkcryptotool-->>Signer: 署名完了通知
        Signer->>Verifier: オリジナルファイルと署名ファイル受け渡し (物理/ネットワーク)
    else 秘密鍵読み込み失敗 (パスフレーズ間違いまたはファイル破損等)
        FileSystem-->>Signer_nkcryptotool: エラー通知
        Signer_nkcryptotool-->>Signer: 署名失敗通知 (秘密鍵ロードエラー)
    end
```

### **署名検証シーケンス (Verifierによる検証)**

```mermaid
sequenceDiagram
    actor Signer
    actor Verifier
    participant Verifier_nkcryptotool as nkcryptotool (検証者側)
    participant FileSystem as ファイルシステム
    participant OpenSSL as OpenSSLライブラリ

    Signer->>Verifier: オリジナルファイルと署名ファイル受け渡し (物理/ネットワーク)
    Verifier->>Verifier_nkcryptotool: 署名検証コマンド実行<br>(オリジナルファイル, 署名ファイル, 署名者公開鍵ファイル)
    Verifier_nkcryptotool->>FileSystem: 署名者公開鍵読み込み
    FileSystem-->>Verifier_nkcryptotool: 署名者公開鍵データ
    Verifier_nkcryptotool->>FileSystem: オリジナルファイル読み込み
    FileSystem-->>Verifier_nkcryptotool: オリジナルファイルデータ
    Verifier_nkcryptotool->>OpenSSL: オリジナルファイルデータのハッシュ計算要求<br>(ダイジェストアルゴリズム)
    OpenSSL-->>Verifier_nkcryptotool: 計算されたハッシュ値 (ダイジェスト)
    Verifier_nkcryptotool->>FileSystem: 署名ファイル読み込み
    FileSystem-->>Verifier_nkcryptotool: 署名データ
    Verifier_nkcryptotool->>OpenSSL: 署名検証要求<br>(ECC: ECDSA, PQC: ML-DSA)
    OpenSSL-->>Verifier_nkcryptotool: 検証結果 (成功/失敗)
    alt 検証成功
        Verifier_nkcryptotool-->>Verifier: 署名検証成功通知<br>(ファイルは認証され、改ざんされていません)
    else 検証失敗
        Verifier_nkcryptotool-->>Verifier: 署名検証失敗通知<br>(ファイルは改ざんされたか、署名が不正です)
    end 
```

## **相互運用性 (Interoperability)**

本プロジェクトは、異なる環境間での「完全な透明性」を目標に設計されています。

*   **実装・バックエンド間の完全互換**: C++版（OpenSSL/wolfSSL）と Rust版（OpenSSL/RustCrypto）は、バイナリレベルで 100% 互換です。
*   **鍵の交換可能性 (Key Interchangeability)**: いかなるバックエンドで生成された鍵ペア（ECC/PQC/Hybrid）も、他のすべてのバックエンドで**変換なしにそのまま利用可能**です。
    *   例: Rust 純 Rust (RustCrypto) 版で生成した PQC 秘密鍵を、C++ wolfSSL版でロードして復号できます。
*   **標準フォーマットの採用**: 鍵は PKCS#8/SPKI、署名は ASN.1 DER 形式、暗号化は標準的な AES-256-GCM (1 file, 1 tag) を採用しており、既存の暗号インフラとの高い親和性を確保しています。

## **ライセンス**

This project is licensed under the **MIT License**.

See the [LICENSE.txt](LICENSE.txt) file for details.

## 📄 Dependencies and Third-Party Licenses

This application redistributes several runtime DLLs required for execution on Windows systems. These DLLs are provided under permissive licenses:

### Compliance Notes

- All LGPL-licensed DLLs are dynamically linked, and their replacement by the user is permitted.
- Full license texts for all dependencies are included in the LICENSES/ directory of the distribution package.
- No modifications have been made to the original libraries.
- The source code for these libraries is available from their respective upstream repositories.

For more details, see the `LICENSES/` folder included in the distribution package.

