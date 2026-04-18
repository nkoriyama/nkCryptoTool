# **nkCryptoTool**

**nkCryptoToolは、次世代暗号技術を含む高度な暗号処理をコマンドラインで手軽にセキュアに実行できるツールです。**

**初めてお使いの方や、暗号技術に詳しくない方は、まずこちらの [GETTING_STARTED.md](GETTING_STARTED.md) をご覧ください。**

* **データの暗号化・復号**: 秘密の情報を安全にやり取りできます。
* **認証付き暗号 (AES-256-GCM)**: すべての暗号化処理において、データの機密性に加え、改ざんを検知する完全性も保証するAES-256-GCMモードを採用しています。  
* **デジタル署名・検証**: ファイルの改ざんを検出し、作成者を証明できます。  
* **ECC (楕円曲線暗号)** および **PQC (耐量子計算機暗号)**、さらにRFC 9180の設計思想に基づきPQC (ML-KEM)とECC (ECDH)を組み合わせた**ハイブリッド暗号**に対応。  
* **TPM (Trusted Platform Module) による秘密鍵の保護**: 秘密鍵をマシンのハードウェア (TPM) に紐付けて安全にラッピング保存できます。原本（生鍵）からの再ラッピングやアンラップにも対応し、究極のセキュリティとポータビリティを両立しています。
* **安定したストリーミング処理**: Asioライブラリの非同期I/Oとパイプライン設計により、5GB以上の巨大なファイルも **3GiB/s を超える圧倒的な高速スループット**で安定して暗号化・復号できます。 (PQCの署名・検証はML-DSAの仕様制限により一括処理)


## **はじめに (How to Get Started)**

このツールは、暗号技術の知識を持つ開発者向けに設計されています。

1. **ビルド**: [ビルド方法](#ビルド方法) セクションを参照し、OpenSSL などの依存ライブラリをセットアップしてプログラムをビルドします。  
2. **使用**: [使用法](#使用法) セクションで、各機能のコマンドラインオプションと具体的な実行例を確認できます。

**暗号初心者の方や、まずは簡単に試してみたい方は、[GETTING_STARTED.md](GETTING_STARTED.md) をご覧ください。**

## **詳細情報 (More Information)**

*   **高速化の秘訣**: 本ツールのパフォーマンス最適化に関する詳細な情報は、[nkCryptoTool_optimization_secrets.md](nkCryptoTool_optimization_secrets.md) をご覧ください。
*   **ベンチマーク実績**: 5GBの大容量ファイルを用いた測定において、**最大 3.3 GiB/s** のスループットを実証しています。詳細は [nkCryptoToolBenchmark](#ベンチマーク) を実行してご確認ください。

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
   cmake \-B build \-G "Ninja"  
   cmake \--build build

   *ビルドが成功すると、実行可能ファイルが build/bin ディレクトリに生成されます。*

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
    Strategy --> KeyProvider
    KeyProvider --> TPM
    KeyProvider --> SoftwareKey
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

### **復号**

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

## License

This software is licensed under the GNU Lesser General Public License v3.0.
See the LICENSE.txt file for details.

## 📄 Dependencies and Third-Party Licenses

This application redistributes several runtime DLLs required for execution on Windows systems. These DLLs are provided under permissive licenses:

### Included DLLs and Licenses

| DLL Name                | License            |
|------------------------|--------------------|
| libgcc_s_seh-1.dll     | LGPL v3 with GCC Runtime Library Exception*|
| libwinpthread-1.dll    | LGPL v3 |
| libstdc++-6.dll        | LGPL v3 with GCC Runtime Library Exception*|
| libcrypto-3-x64.dll    | Apache License 2.0 |

* These libraries are licensed under the LGPL v3 with the GCC Runtime Library Exception, which allows them to be linked with proprietary applications. See the included license texts for full details.

### Compliance Notes

- All LGPL-licensed DLLs are dynamically linked, and their replacement by the user is permitted.
- Full license texts for all dependencies are included in the LICENSES/ directory of the distribution package.
- No modifications have been made to the original libraries.
- The source code for these libraries is available from their respective upstream repositories.

For more details, see the `LICENSES/` folder included in the distribution package.

