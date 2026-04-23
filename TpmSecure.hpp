#ifndef TPM_SECURE_HPP
#define TPM_SECURE_HPP

#include <vector>
#include <string>
#include <iostream>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <openssl/crypto.h>
#include <filesystem>
#include "SecureMemory.hpp"
#include "CryptoError.hpp"

extern "C" char** environ;

namespace nk {

/**
 * セキュアな一時ディレクトリのパスを取得/作成する。
 * ~/.cache/nkCryptoTool/tmp/ を使用し、初回アクセス時に 0700 で作成。
 */
inline std::filesystem::path get_secure_tmp_dir() {
    static std::filesystem::path dir = []() {
        auto home = std::getenv("HOME");
        if (!home) {
            // Fallback: use system temp directory
            return std::filesystem::temp_directory_path();
        }
        std::filesystem::path d = std::filesystem::path(home) / ".cache" / "nkCryptoTool" / "tmp";
        std::error_code ec;
        if (!std::filesystem::exists(d, ec) || ec) {
            std::filesystem::create_directories(d, ec);
            if (!ec) {
                // chmod 0700 - owner only
                std::filesystem::permissions(d,
                    std::filesystem::perms::owner_all |
                    std::filesystem::perms::owner_read |
                    std::filesystem::perms::owner_write |
                    std::filesystem::perms::owner_exec,
                    std::filesystem::perm_options::add);
                chmod(d.c_str(), S_IRWXU);
            }
        }
        return d;
    }();
    return dir;
}

/**
 * セキュアな一時ファイルパスを生成し、mkstemp用のテンプレート文字列を返す。
 * 実際のファイル作成は呼び出し側で mkstemp を行う。
 */
inline std::string make_secure_tmp_template(const std::string& prefix = "nk_") {
    return (get_secure_tmp_dir() / (prefix + "XXXXXX")).string();
}

} // namespace nk

namespace nk {

/**
 * コマンド実行結果を格納する構造体
 */
struct CommandResult {
    int exit_code = -1;
    std::string stdout_str;
    std::string stderr_str;
};

/**
 * 安全なコマンド実行関数
 * シェルを介さず、引数を直接渡し、タイムアウトと非同期I/Oをサポートする。
 */
inline CommandResult run_cmd_secure(const std::vector<std::string>& args, 
                                    const SecureString& stdin_data = "", 
                                    int timeout_ms = 30000) {
    CommandResult result;
    int pipe_in[2] = {-1, -1}, pipe_out[2] = {-1, -1}, pipe_err[2] = {-1, -1};

    if (pipe(pipe_in) != 0 || pipe(pipe_out) != 0 || pipe(pipe_err) != 0) {
        throw std::runtime_error("Failed to create pipes");
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipe_in[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipe_out[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipe_err[1], STDERR_FILENO);
    
    // 子プロセス側で不要なパイプ端を閉じる
    posix_spawn_file_actions_addclose(&actions, pipe_in[1]);
    posix_spawn_file_actions_addclose(&actions, pipe_out[0]);
    posix_spawn_file_actions_addclose(&actions, pipe_err[0]);

    std::vector<char*> argv;
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    // 環境変数の設定 (TCTI)
    std::vector<std::string> env_strings;
    env_strings.push_back("TCTI=device:/dev/tpmrm0");
    for (char** env = environ; *env != nullptr; ++env) {
        if (strncmp(*env, "TCTI=", 5) != 0) {
            env_strings.push_back(*env);
        }
    }
    std::vector<char*> envp;
    for (const auto& s : env_strings) envp.push_back(const_cast<char*>(s.c_str()));
    envp.push_back(nullptr);

    pid_t pid;
    if (posix_spawn(&pid, argv[0], &actions, nullptr, argv.data(), envp.data()) != 0) {
        posix_spawn_file_actions_destroy(&actions);
        for(int fd : {pipe_in[0], pipe_in[1], pipe_out[0], pipe_out[1], pipe_err[0], pipe_err[1]}) if(fd != -1) close(fd);
        throw std::runtime_error("Failed to spawn process: " + args[0]);
    }

    posix_spawn_file_actions_destroy(&actions);
    close(pipe_in[0]);
    close(pipe_out[1]);
    close(pipe_err[1]);

    // 非ブロッキングモードに設定
    fcntl(pipe_out[0], F_SETFL, O_NONBLOCK);
    fcntl(pipe_err[0], F_SETFL, O_NONBLOCK);
    fcntl(pipe_in[1], F_SETFL, O_NONBLOCK);

    size_t stdin_written = 0;
    bool in_open = !stdin_data.empty();
    if (stdin_data.empty()) close(pipe_in[1]);

    auto start_time = std::chrono::steady_clock::now();
    pollfd fds[3];
    fds[0].fd = pipe_out[0]; fds[0].events = POLLIN;
    fds[1].fd = pipe_err[0]; fds[1].events = POLLIN;
    fds[2].fd = in_open ? pipe_in[1] : -1; fds[2].events = POLLOUT;

    while (fds[0].fd != -1 || fds[1].fd != -1 || fds[2].fd != -1) {
        auto now = std::chrono::steady_clock::now();
        int elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed > timeout_ms) {
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            throw std::runtime_error("Command timed out: " + args[0]);
        }

        int ret = poll(fds, 3, 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        char buffer[4096];
        if (fds[0].revents & (POLLIN | POLLHUP)) {
            ssize_t n = read(pipe_out[0], buffer, sizeof(buffer));
            if (n > 0) result.stdout_str.append(buffer, n);
            else if (n == 0 || (n < 0 && errno != EAGAIN)) {
                close(pipe_out[0]);
                fds[0].fd = -1;
            }
        }
        if (fds[1].revents & (POLLIN | POLLHUP)) {
            ssize_t n = read(pipe_err[0], buffer, sizeof(buffer));
            if (n > 0) result.stderr_str.append(buffer, n);
            else if (n == 0 || (n < 0 && errno != EAGAIN)) {
                close(pipe_err[0]);
                fds[1].fd = -1;
            }
        }
        if (fds[2].fd != -1 && (fds[2].revents & POLLOUT)) {
            ssize_t n = write(pipe_in[1], stdin_data.data() + stdin_written, stdin_data.size() - stdin_written);
            if (n > 0) {
                stdin_written += n;
                if (stdin_written >= stdin_data.size()) {
                    close(pipe_in[1]);
                    fds[2].fd = -1;
                }
            } else if (n < 0 && errno != EAGAIN) {
                close(pipe_in[1]);
                fds[2].fd = -1;
            }
        }
        
        int status;
        if (waitpid(pid, &status, WNOHANG) > 0) {
            if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
            else if (WIFSIGNALED(status)) result.exit_code = -WTERMSIG(status);
        }
    }

    int status;
    waitpid(pid, &status, 0);
    if (result.exit_code == -1) {
        if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) result.exit_code = -WTERMSIG(status);
    }

    return result;
}

/**
 * TPMセッション管理RAIIクラス
 */
class TpmSession {
public:
    // セッション開始 (アンバインドHMACセッション)
    TpmSession() {
        std::string tmpl = nk::make_secure_tmp_template("nk_sess_");
        char temp_path[1024];
        std::strncpy(temp_path, tmpl.c_str(), sizeof(temp_path) - 1);
        temp_path[sizeof(temp_path) - 1] = '\0';
        int fd = mkstemp(temp_path);
        if (fd == -1) throw std::runtime_error("Failed to create TPM session file");
        close(fd);
        session_path_ = temp_path;

        auto res = run_cmd_secure({"/usr/bin/tpm2_startauthsession", "--hmac-session", "-S", session_path_});
        if (res.exit_code != 0) {
            unlink(session_path_.c_str());
            throw std::runtime_error("Failed to start TPM session: " + res.stderr_str);
        }
    }

    ~TpmSession() {
        if (!session_path_.empty()) {
            std::vector<std::string> args = {"/usr/bin/tpm2_flushcontext", session_path_};
            try {
                run_cmd_secure(args);
            } catch (...) {}
            unlink(session_path_.c_str());
        }
    }

    std::string getSessionPath() const { return session_path_; }
    std::string getSessionArg() const { return "session:" + session_path_; }

private:
    std::string session_path_;
};

/**
 * パスワード一時ファイル管理RAIIクラス
 * tpm2-tools の file: 形式で使用する
 */
class TpmPasswordFile {
public:
    TpmPasswordFile(const SecureString& password) {
        std::string tmpl = nk::make_secure_tmp_template("nk_pw_");
        char temp_path[1024];
        std::strncpy(temp_path, tmpl.c_str(), sizeof(temp_path) - 1);
        temp_path[sizeof(temp_path) - 1] = '\0';
        int fd = mkstemp(temp_path);
        if (fd == -1) throw std::runtime_error("Failed to create temporary password file");
        
        // 権限を600に制限
        fchmod(fd, 0600);
        
        if (write(fd, password.data(), password.size()) != static_cast<ssize_t>(password.size())) {
            close(fd);
            unlink(temp_path);
            throw std::runtime_error("Failed to write password to temporary file");
        }
        close(fd);
        path_ = temp_path;
    }

    ~TpmPasswordFile() {
        if (!path_.empty()) {
            // メモリ上のパスワードは SecureString がクリーンアップするが、
            // ファイルについては削除前に上書きを試みる（簡易的なクリーンアップ）
            std::ofstream ofs(path_, std::ios::binary);
            if (ofs) {
                std::vector<char> zero(1024, 0);
                ofs.write(zero.data(), zero.size());
                ofs.flush();
            }
            unlink(path_.c_str());
        }
    }

    std::string getPath() const { return path_; }
    std::string getFileArg() const { return "file:" + path_; }

private:
    std::string path_;
};

} // namespace nk

#endif // TPM_SECURE_HPP
