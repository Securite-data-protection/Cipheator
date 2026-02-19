#include "cipheator/gost_cli.h"

#include "cipheator/bytes.h"

#include <filesystem>
#include <sstream>
#include <cstdlib>
#include <chrono>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
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
  int code = std::system(cmd.c_str());
  if (code != 0) {
    if (err) {
      *err = "Command failed: " + cmd;
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
  cmd << enc_cmd << " " << quote_path(input_path.string());
  if (!run_command(cmd.str(), err)) return false;

  fs::path enc_path = input_path;
  enc_path += config_.enc_suffix;
  fs::path key_path = input_path;
  key_path += config_.key_suffix;

  bool ok = false;
  out->data = read_file(enc_path.string(), &ok);
  if (!ok) {
    if (err) *err = "Failed to read encrypted file";
    return false;
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
  fs::path enc_path = temp.path() / "input.bin";
  enc_path += config_.enc_suffix;
  fs::path key_path = temp.path() / "input.bin";
  key_path += config_.key_suffix;

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
      << quote_path(key_path.string());
  if (!run_command(cmd.str(), err)) return false;

  fs::path out_path = enc_path;
  std::string enc_suffix = config_.enc_suffix;
  if (!enc_suffix.empty()) {
    std::string out_str = out_path.string();
    if (out_str.size() >= enc_suffix.size() &&
        out_str.substr(out_str.size() - enc_suffix.size()) == enc_suffix) {
      out_str = out_str.substr(0, out_str.size() - enc_suffix.size());
      out_path = out_str;
    }
  }

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
