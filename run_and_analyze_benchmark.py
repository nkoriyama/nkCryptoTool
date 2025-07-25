import subprocess
import json
import os
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# --- 設定項目 ---

# ベンチマーク実行可能ファイルのパス
# このスクリプトをプロジェクトのルートディレクトリで実行することを想定
BENCHMARK_EXE_PATH = os.path.join("build", "bin", "nkCryptoToolBench.exe")

# ベンチマーク結果を出力するJSONファイルのパス
RESULT_JSON_PATH = "benchmark_results.json"

# ベンチマーク対象のファイルサイズ (MiB単位)
# benchmark/BenchMain.cpp の設定と合わせてください
FILE_SIZE_MIB = 6408

# --- スクリプト本体 ---

def run_benchmark():
    """ベンチマークを実行し、結果をJSONファイルに出力する"""
    print("--- ベンチマーク実行開始 ---")

    if not os.path.exists(BENCHMARK_EXE_PATH):
        print("エラー: ベンチマーク実行可能ファイルが見つかりません。")
        print("パス: {}".format(os.path.abspath(BENCHMARK_EXE_PATH)))
        print("先に `cmake --build build` を実行してください。")
        sys.exit(1)

    command = [
        BENCHMARK_EXE_PATH,
        "--benchmark_out={}".format(RESULT_JSON_PATH),
        "--benchmark_out_format=json"
    ]

    try:
        # ベンチマークは時間がかかるため、進捗がわかるように出力を表示する
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
        
        # リアルタイムで出力を表示
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())

        return_code = process.poll()

        if return_code != 0:
            print("""\nエラー: ベンチマークの実行に失敗しました。(リターンコード: {})\n""".format(return_code))
            sys.exit(1)
        
        print("\n--- ベンチマーク実行完了 ---")
        return True

    except FileNotFoundError:
        print("エラー: コマンドが見つかりません - {}".format(command[0]))
        return False
    except Exception as e:
        print("ベンチマーク実行中に予期せぬエラーが発生しました: {}".format(e))
        return False

def analyze_results():
    """JSONファイルを読み込み、結果を解析して表示する"""
    print("\n--- 結果の解析 ---")

    if not os.path.exists(RESULT_JSON_PATH):
        print("エラー: 結果ファイルが見つかりません - {}".format(RESULT_JSON_PATH))
        return

    with open(RESULT_JSON_PATH, 'r') as f:
        data = json.load(f)

    # 1. 実行環境の表示
    context = data.get("context", {})
    print("\n[実行環境]")
    print("  実行日時: {}".format(context.get('date')))
    print("  CPU: {} cores @ {} MHz".format(context.get('num_cpus'), context.get('mhz_per_cpu')))
    
    # 2. ベンチマーク結果の解析と表示
    file_size_gib = FILE_SIZE_MIB / 1024
    print("\n[ベンチマーク結果 (ファイルサイズ: {:.2f} GiB)]".format(file_size_gib))
    
    file_size_bytes = FILE_SIZE_MIB * 1024 * 1024
    file_size_mb = FILE_SIZE_MIB

    for benchmark in data.get("benchmarks", []):
        name = benchmark.get("name")
        real_time_ns = benchmark.get("real_time")
        cpu_time_ns = benchmark.get("cpu_time")
        time_unit = benchmark.get("time_unit")

        if time_unit != "ns":
            print("警告: 予期しない時間単位({})のため、スループット計算をスキップします。".format(time_unit))
            continue

        # 時間を秒に変換
        real_time_s = real_time_ns / 1e9
        cpu_time_s = cpu_time_ns / 1e9

        # スループットを計算 (MB/s)
        # real_time_s が0の場合は計算しない
        throughput_real = (file_size_mb / real_time_s) if real_time_s > 0 else 0
        throughput_cpu = (file_size_mb / cpu_time_s) if cpu_time_s > 0 else 0

        print("\n- テスト名: {}".format(name))
        print("  - 実時間 (Wall Time): {:.4f} 秒".format(real_time_s))
        print("  - CPU時間 (CPU Time):  {:.4f} 秒".format(cpu_time_s))
        print("  - スループット (実時間ベース): {:.2f} MB/s".format(throughput_real))
        print("  - スループット (CPU時間ベース):  {:.2f} MB/s".format(throughput_cpu))

    print("""\n--- 解析完了 ---
""")


if __name__ == "__main__":
    if run_benchmark():
        analyze_results()