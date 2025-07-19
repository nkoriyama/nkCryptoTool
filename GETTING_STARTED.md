# **nkCryptoTool を始めよう**

### **1\. はじめに：nkCryptoToolって何？**

nkCryptoTool は、あなたのデジタルな情報を「秘密に守る」ことや、「本物であることを証明する」ことができるツールです。

* **秘密に守る（暗号化・復号）**: 大切なメッセージやファイルを、特定の人しか読めないように変換し（暗号化）、後で元の情報に戻す（復号）ことができます。  
* **本物であることを証明する（デジタル署名・検証）**: ファイルが途中で誰かに改ざんされていないか確認したり、そのファイルが「あなたが作ったものだ」という証明を付けたりできます。

このツールは、最新の暗号技術である「ECC（楕円曲線暗号）」や、将来の量子コンピューターにも強いとされる「PQC（耐量子計算機暗号）」に対応しています。

### **2\. まずは動かしてみよう！**

ここでは、最も簡単な方法で nkCryptoTool を動かしてみましょう。

#### **ステップ1: 環境を準備しよう (Docker推奨)**

一番簡単な方法は、Docker を使うことです。Docker がインストールされていれば、複雑な設定なしにすぐに始められます。

* Docker Desktop をインストール:  
  お使いのOS（Windows, macOS, Linux）に合わせて、Docker Desktop の公式サイト からダウンロードしてインストールしてください。  
* Docker コンテナを起動（例：Ubuntu環境）:  
  ターミナル（コマンドプロンプトやPowerShell）を開き、以下のコマンドを実行します。  
  docker run \-it ubuntu:latest /bin/bash

  これにより、Ubuntu環境が起動し、その中でコマンドを実行できるようになります。

#### **ステップ2: ツールをダウンロード＆ビルドしよう**

Dockerコンテナ内（またはご自身の開発環境）で、以下のコマンドを実行します。

##### **必要なツールのインストール (Ubuntuの場合)**

apt update && apt install \-y git cmake build-essential ninja-build libssl-dev

##### **nkCryptoToolをダウンロード**

git clone https://github.com/nkoriyama/nkCryptToool  
cd nkCryptToool

##### **ビルドディレクトリを作成し、ビルド**

mkdir build  
cd build  
cmake \-G "Ninja" ..  
cmake \--build .

ビルドが成功すると、./bin ディレクトリの中に nkCryptoTool という実行ファイルが作成されます。

#### **ステップ3: 最初の暗号化・復号を体験しよう！（ECCモードで）**

ここでは、最も一般的な「ECC（楕円曲線暗号）」を使って、ファイルの暗号化と復号を試します。

##### **鍵ペアを生成:**

暗号化と復号に必要な「秘密鍵」と「公開鍵」のペアを作成します。

./bin/nkCryptoTool \--mode ecc \--gen-enc-key

実行するとパスフレーズの入力を求められます。今回は練習なので、何も入力せずに Enter キーを2回押してください。成功すると、keys ディレクトリに public\_enc\_ecc.key と private\_enc\_ecc.key が作成されます。

##### **暗号化したいメッセージをファイルに保存:**

適当なテキストエディタで original.txt というファイルを作成し、中に何か秘密のメッセージを書き込んで保存してください。  
（例: echo "こんにちは、世界！これは秘密のメッセージです。" \> original.txt）

##### **メッセージを暗号化する:**

original.txt を暗号化し、encrypted.bin というファイルに出力します。--recipient-pubkey には、相手の（今回は自分自身の）公開鍵を指定します。

./bin/nkCryptoTool \--mode ecc \--encrypt \--recipient-pubkey keys/public\_enc\_ecc.key \-o encrypted.bin original.txt

成功すると、「Encryption to '...encrypted.bin' completed.」のようなメッセージが表示されます。

##### **メッセージを復号する:**

暗号化された encrypted.bin を復号し、decrypted.txt というファイルに出力します。--user-privkey には自分の秘密鍵を指定します。

./bin/nkCryptoTool \--mode ecc \--decrypt \--user-privkey keys/private\_enc\_ecc.key \-o decrypted.txt encrypted.bin

実行するとパスフレーズの入力を求められますが、鍵生成時にパスフレーズを設定していない場合は何も入力せずに Enter キーを押してください。成功すると、「Decryption to '...decrypted.txt' completed.」のようなメッセージが表示されます。decrypted.txt の中身を確認し、元のメッセージが読めることを確認してください。



#### **ステップ4: 最初の署名・検証を体験しよう！（ECCモードで）**

次に、ファイルが改ざんされていないことを確認する「デジタル署名」を試します。

##### **署名鍵ペアを生成:**

署名と検証に必要な鍵ペアを作成します。

./bin/nkCryptoTool \--mode ecc \--gen-sign-key

パスフレーズは何も入力せずに Enter キーを2回押してください。keys ディレクトリに public\_sign\_ecc.key と private\_sign\_ecc.key が作成されます。

##### **ファイルを署名する:**

original.txt にデジタル署名を行います。署名データは original.sig に出力されます。

./bin/nkCryptoTool \--mode ecc \--sign original.txt \--signature original.sig \--signing-privkey keys/private\_sign\_ecc.key

パスフレーズは何も入力せずに Enter キーを押してください。成功すると、「File signed successfully.」のようなメッセージが表示されます。

##### **署名を検証する:**

original.txt と original.sig、そして署名者の公開鍵を使って署名を検証します。

./bin/nkCryptoTool \--mode ecc \--verify original.txt \--signature original.sig \--signing-pubkey keys/public\_sign\_ecc.key

成功すると、「Signature verified successfully.」のようなメッセージが表示されます。もし original.txt の中身を少しでも変更してから検証すると、検証が失敗することを確認できます。

### **3. もう少し深く知りたい方へ**

おめでとうございます！これで nkCryptoTool の基本的な使い方を体験できました。

*   PQC（耐量子計算機暗号） を試したい方
*   もっと詳しいコマンドオプションや、各アルゴリズムの動作原理を知りたい方
*   開発環境のセットアップについてより詳細な情報が必要な方

これらについては、[**nkCryptoTool 操作ガイド (wizard.md)**](wizard.md) またはメインの [**README.md**](README.md) を参照してください。