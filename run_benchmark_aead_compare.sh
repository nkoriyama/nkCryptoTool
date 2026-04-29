#!/bin/bash
INPUT="gemma_sample.gguf"
SIZE_GB=2
ENC_OUT="enc.tmp"
DEC_OUT="dec.tmp"
KEY_DIR="bench_keys_final"
RESULTS="benchmark_results_final.csv"

echo "Language,Backend,AEAD,Mode,Operation,Time(s),Throughput(GiB/s)" > $RESULTS

run_bench() {
    local lang=$1; local backend=$2; local bin=$3; local aead=$4; local mode=$5
    echo "Benchmarking $lang $backend $aead $mode..."
    
    local out_opt="-o"
    [[ "$bin" == *nk-crypto-tool* ]] && out_opt="--output-file"
    
    local aead_arg="--aead-algo $aead"
    
    # Encryption Command
    local cmd_enc=""
    if [ "$mode" == "ecc" ]; then
        cmd_enc="$bin --mode ecc --encrypt $aead_arg --recipient-pubkey $KEY_DIR/public_enc_ecc.key $out_opt $ENC_OUT $INPUT"
    elif [ "$mode" == "pqc" ]; then
        cmd_enc="$bin --mode pqc --encrypt $aead_arg --recipient-pubkey $KEY_DIR/public_enc_pqc.key $out_opt $ENC_OUT $INPUT"
    elif [ "$mode" == "hybrid" ]; then
        cmd_enc="$bin --mode hybrid --encrypt $aead_arg --recipient-mlkem-pubkey $KEY_DIR/public_enc_hybrid_mlkem.key --recipient-ecdh-pubkey $KEY_DIR/public_enc_hybrid_ecdh.key $out_opt $ENC_OUT $INPUT"
    fi
    
    # Decryption Command
    local cmd_dec=""
    if [ "$mode" == "ecc" ]; then
        cmd_dec="$bin --mode ecc --decrypt $out_opt $DEC_OUT $ENC_OUT --user-privkey $KEY_DIR/private_enc_ecc.key"
    elif [ "$mode" == "pqc" ]; then
        cmd_dec="$bin --mode pqc --decrypt $out_opt $DEC_OUT $ENC_OUT --user-privkey $KEY_DIR/private_enc_pqc.key"
    elif [ "$mode" == "hybrid" ]; then
        cmd_dec="$bin --mode hybrid --decrypt $out_opt $DEC_OUT $ENC_OUT --user-mlkem-privkey $KEY_DIR/private_enc_hybrid_mlkem.key --user-ecdh-privkey $KEY_DIR/private_enc_hybrid_ecdh.key"
    fi

    # Run Encrypt
    start=$(date +%s.%N)
    if [[ "$bin" == *nk-crypto-tool* ]]; then
        NK_PASSPHRASE="" eval "$cmd_enc" > /dev/null 2>&1
    else
        eval "$cmd_enc" > /dev/null 2>&1
    fi
    ret_enc=$?
    end=$(date +%s.%N)
    
    if [ $ret_enc -eq 0 ]; then
        runtime=$(echo "$end - $start" | bc); tp=$(echo "scale=2; $SIZE_GB / $runtime" | bc)
        echo "$lang,$backend,$aead,$mode,Encrypt,$runtime,$tp" >> $RESULTS
    else
        echo "$lang,$backend,$aead,$mode,Encrypt,FAILED,0" >> $RESULTS
    fi
    
    # Run Decrypt
    if [ $ret_enc -eq 0 ] && [ -f $ENC_OUT ]; then
        start=$(date +%s.%N)
        if [[ "$bin" == *nk-crypto-tool* ]]; then
            NK_PASSPHRASE="" eval "$cmd_dec" > /dev/null 2>&1
        else
            eval "$cmd_dec" > /dev/null 2>&1
        fi
        ret_dec=$?
        end=$(date +%s.%N)
        
        if [ $ret_dec -eq 0 ]; then
            runtime=$(echo "$end - $start" | bc); tp=$(echo "scale=2; $SIZE_GB / $runtime" | bc)
            echo "$lang,$backend,$aead,$mode,Decrypt,$runtime,$tp" >> $RESULTS
        else
            echo "$lang,$backend,$aead,$mode,Decrypt,FAILED,0" >> $RESULTS
        fi
    else
        echo "$lang,$backend,$aead,$mode,Decrypt,FAILED,0" >> $RESULTS
    fi

    rm -f $ENC_OUT $DEC_OUT
}

# Run all combinations
backends=("C++ OpenSSL ./nkCryptoTool/build/nkCryptoTool" 
          "C++ wolfSSL ./nkCryptoTool/build_wolfssl/nkCryptoTool"
          "Rust OpenSSL ./nkCryptoTool-rust/target/release/nk-crypto-tool"
          "Rust RustCrypto ./nkCryptoTool-rust/target_rustcrypto/release/nk-crypto-tool")

aeads=("AES-256-GCM" "ChaCha20-Poly1305")
modes=("ecc" "hybrid")

for b in "${backends[@]}"; do
    read -r lang backend bin <<< "$b"
    for aead in "${aeads[@]}"; do
        for mode in "${modes[@]}"; do
            run_bench "$lang" "$backend" "$bin" "$aead" "$mode"
        done
    done
done

echo "Benchmark finished. Results:"
column -t -s, $RESULTS
