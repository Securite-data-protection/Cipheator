#include "cipheator/gost_cli.h"

#include "cipheator/bytes.h"

#include <filesystem>
#include <sstream>
#include <cstdlib>
#include <chrono>
#include <fstream>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace fs = std::filesystem;

namespace cipheator {

namespace {

std::string quote_path(const std::string& path) {
  std::string out = "\"";
  out += path;
  out += "\"";
  return out;
}

class TempDir {
 public:
  TempDir() {
    fs::path base = fs::temp_directory_path();
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
#if defined(_WIN32)
    std::string name = "cipheator_gost_" + std::to_string(_getpid()) + "_" + std::to_string(now);
#else
    std::string name = "cipheator_gost_" + std::to_string(getpid()) + "_" + std::to_string(now);
#endif
    path_ = base / name;
    fs::create_directories(path_);
  }

  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }

  const fs::path& path() const { return path_; }

 private:
  fs::path path_;
};

} // namespace

GostCli::GostCli(GostCliConfig config) : config_(std::move(config)) {}

bool GostCli::run_command(const std::string& cmd, std::string* err) {
  fs::path log_path = fs::temp_directory_path() /
                      ("cipheator_gost_cmd_" +
#if defined(_WIN32)
                       std::to_string(_getpid()) +
#else
                       std::to_string(getpid()) +
#endif
                       "_" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()) +
                       ".log");
  std::string wrapped = cmd + " > " + quote_path(log_path.string()) + " 2>&1";
  int code = std::system(wrapped.c_str());
  std::string output;
  {
    std::ifstream in(log_path);
    if (in) {
      std::ostringstream ss;
      ss << in.rdbuf();
      output = ss.str();
    }
    std::error_code ec;
    fs::remove(log_path, ec);
  }
  if (code != 0) {
    if (err) {
      int exit_code = code;
#if !defined(_WIN32)
      if (WIFEXITED(code)) {
        exit_code = WEXITSTATUS(code);
      }
#endif
      *err = "Command failed (exit=" + std::to_string(exit_code) + "): " + cmd;
      if (!output.empty()) {
        *err += " | output: " + output;
      }
    }
    return false;
  }
  return true;
}

bool GostCli::encrypt(Cipher cipher,
                      const std::vector<uint8_t>& plaintext,
                      CryptoResult* out,
                      std::string* err) {
  if (!out) return false;

  TempDir temp;
  fs::path input_path = temp.path() / "input.bin";
  if (!write_file(input_path.string(), plaintext)) {
    if (err) *err = "Failed to write temp input file";
    return false;
  }

  std::string enc_cmd;
  if (cipher == Cipher::MAGMA) {
    enc_cmd = config_.enc_magma;
  } else if (cipher == Cipher::KUZNECHIK) {
    enc_cmd = config_.enc_kuznechik;
  } else {
    if (err) *err = "Unsupported GOST cipher";
    return false;
  }

  std::ostringstream cmd;
  fs::path enc_path = temp.path() / "encrypted.bin";
  fs::path key_path = temp.path() / "key.bin";
  cmd << enc_cmd << " " << quote_path(input_path.string()) << " "
      << quote_path(enc_path.string()) << " " << quote_path(key_path.string());
  std::string first_err;
  if (!run_command(cmd.str(), &first_err)) {
    // Fallback for binaries that accept only two arguments.
    std::ostringstream cmd2;
    cmd2 << enc_cmd << " " << quote_path(input_path.string()) << " "
         << quote_path(enc_path.string());
    if (!run_command(cmd2.str(), err)) {
      if (err) {
        *err = first_err + " | fallback failed: " + *err;
      }
      return false;
    }
  }

  bool ok = false;
  out->data = read_file(enc_path.string(), &ok);
  if (!ok) {
    if (err) *err = "Failed to read encrypted file";
    return false;
  }

  if (!fs::exists(key_path)) {
    std::vector<fs::path> candidates = {
        enc_path.string() + config_.key_suffix,
        input_path.string() + config_.key_suffix,
    };
    for (const auto& p : candidates) {
      if (fs::exists(p)) {
        key_path = p;
        break;
      }
    }
  }

  out->key = read_file(key_path.string(), &ok);
  if (!ok) {
    if (err) *err = "Failed to read key file";
    return false;
  }
  out->iv.clear();
  out->tag.clear();
  return true;
}

bool GostCli::decrypt(Cipher cipher,
                      const std::vector<uint8_t>& ciphertext,
                      const std::vector<uint8_t>& key,
                      CryptoResult* out,
                      std::string* err) {
  if (!out) return false;

  TempDir temp;
  fs::path enc_path = temp.path() / "encrypted.bin";
  fs::path out_path = temp.path() / "output.bin";
  fs::path key_path = temp.path() / "key.bin";

  if (!write_file(enc_path.string(), ciphertext)) {
    if (err) *err = "Failed to write temp encrypted file";
    return false;
  }
  if (!write_file(key_path.string(), key)) {
    if (err) *err = "Failed to write temp key file";
    return false;
  }

  std::string dec_cmd;
  if (cipher == Cipher::MAGMA) {
    dec_cmd = config_.dec_magma;
  } else if (cipher == Cipher::KUZNECHIK) {
    dec_cmd = config_.dec_kuznechik;
  } else {
    if (err) *err = "Unsupported GOST cipher";
    return false;
  }

  std::ostringstream cmd;
  cmd << dec_cmd << " " << quote_path(enc_path.string()) << " "
      << quote_path(out_path.string()) << " " << quote_path(key_path.string());
  if (!run_command(cmd.str(), err)) return false;

  bool ok = false;
  out->data = read_file(out_path.string(), &ok);
  if (!ok) {
    if (err) *err = "Failed to read decrypted file";
    return false;
  }
  out->key.clear();
  out->iv.clear();
  out->tag.clear();
  return true;
}

} // namespace cipheator
