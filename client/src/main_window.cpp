#include "main_window.h"

#include "secure_guards.h"

#include <algorithm>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QFileDialog>
#include <QDialog>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#include <chrono>
#include <filesystem>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#include "cipheator/bytes.h"

namespace {

constexpr size_t kPreviewLimit = 64 * 1024;

bool looks_binary(const uint8_t* data, size_t len) {
  if (!data || len == 0) return false;
  size_t non_printable = 0;
  for (size_t i = 0; i < len; ++i) {
    uint8_t b = data[i];
    if (b == 0) return true;
    if ((b < 9) || (b > 13 && b < 32) || b == 127) {
      non_printable++;
    }
  }
  return (non_printable * 100) / len > 10;
}

QString hex_dump(const uint8_t* data, size_t len) {
  static const char* kHex = "0123456789abcdef";
  QString out;
  out.reserve(static_cast<int>(len * 3));
  const size_t per_line = 16;
  for (size_t i = 0; i < len; ++i) {
    if (i % per_line == 0) {
      out += QString("\n%1  ").arg(static_cast<qulonglong>(i), 6, 16, QChar('0'));
    }
    out += QChar(kHex[(data[i] >> 4) & 0xF]);
    out += QChar(kHex[data[i] & 0xF]);
    out += QChar(' ');
  }
  if (!out.isEmpty()) {
    out.remove(0, 1);
  }
  return out;
}

std::string temp_base_dir() {
  namespace fs = std::filesystem;
  std::error_code ec;
#if !defined(_WIN32)
  fs::path shm("/dev/shm");
  if (fs::exists(shm, ec) && fs::is_directory(shm, ec)) {
    return shm.string();
  }
#endif
  fs::path base = fs::temp_directory_path(ec);
  if (ec) {
    return fs::current_path().string();
  }
  return base.string();
}

std::string make_temp_path(const QString& original_path) {
  namespace fs = std::filesystem;
  static uint64_t counter = 0;
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  fs::path base = temp_base_dir();
  fs::path name = fs::path(original_path.toStdString()).filename();
  std::string suffix = std::to_string(now) + "_" + std::to_string(counter++);
  fs::path out = base / ("cipheator_tmp_" + suffix + "_" + name.string());
  return out.string();
}

bool write_temp_file(const cipheator::SecureBuffer& data,
                     const std::string& path,
                     std::string* err) {
  std::vector<uint8_t> tmp(data.data(), data.data() + data.size());
  bool ok = cipheator::write_file(path, tmp);
  if (!tmp.empty()) {
    cipheator::secure_zero(tmp.data(), tmp.size());
  }
  if (!ok) {
    if (err) *err = "Failed to write temp file";
    return false;
  }
#if !defined(_WIN32)
  chmod(path.c_str(), 0600);
#endif
  return true;
}

cipheator::Cipher cipher_from_index(int index) {
  switch (index) {
    case 0:
      return cipheator::Cipher::AES_256_GCM;
    case 1:
      return cipheator::Cipher::AES_256_CBC;
    case 2:
      return cipheator::Cipher::DES_CBC;
    case 3:
      return cipheator::Cipher::DES_ECB;
    case 4:
      return cipheator::Cipher::KUZNECHIK;
    case 5:
      return cipheator::Cipher::MAGMA;
    default:
      return cipheator::Cipher::AES_256_GCM;
  }
}

cipheator::HashAlg hash_from_index(int index) {
  switch (index) {
    case 0:
      return cipheator::HashAlg::SHA256;
    case 1:
      return cipheator::HashAlg::STREEBOG;
    default:
      return cipheator::HashAlg::SHA256;
  }
}

} // namespace

MainWindow::MainWindow(const cipheator::ClientConfig& config,
                       const QString& username,
                       const QString& password,
                       QWidget* parent)
    : QMainWindow(parent),
      client_(config),
      username_(username),
      password_(password),
      default_key_storage_(config.default_key_storage) {
  setWindowTitle("Cipheator");
  auto* central = new QWidget(this);
  auto* layout = new QVBoxLayout(central);

  auto* files_box = new QGroupBox("Selected Files", central);
  auto* files_layout = new QVBoxLayout(files_box);
  file_list_ = new QListWidget(files_box);
  auto* select_btn = new QPushButton("Select Files", files_box);
  connect(select_btn, &QPushButton::clicked, this, &MainWindow::onSelectFiles);
  files_layout->addWidget(file_list_);
  files_layout->addWidget(select_btn);

  auto* settings_box = new QGroupBox("Settings", central);
  auto* settings_layout = new QHBoxLayout(settings_box);

  cipher_combo_ = new QComboBox(settings_box);
  cipher_combo_->addItem("AES-256-GCM");
  cipher_combo_->addItem("AES-256-CBC");
  cipher_combo_->addItem("DES-CBC");
  cipher_combo_->addItem("DES-ECB");
  cipher_combo_->addItem("Kuznechik");
  cipher_combo_->addItem("Magma");

  hash_combo_ = new QComboBox(settings_box);
  hash_combo_->addItem("SHA-256");
  hash_combo_->addItem("Streebog");

  key_storage_combo_ = new QComboBox(settings_box);
  key_storage_combo_->addItem("Server (default)");
  key_storage_combo_->addItem("Client (embedded key)");
  if (default_key_storage_ == "client") {
    key_storage_combo_->setCurrentIndex(1);
  }

  temp_checkbox_ = new QCheckBox("Decrypt to temp file (auto-clean)", settings_box);
  temp_checkbox_->setChecked(config.decrypt_to_temp);

  settings_layout->addWidget(new QLabel("Cipher:", settings_box));
  settings_layout->addWidget(cipher_combo_);
  settings_layout->addWidget(new QLabel("Hash:", settings_box));
  settings_layout->addWidget(hash_combo_);
  settings_layout->addWidget(new QLabel("Key storage:", settings_box));
  settings_layout->addWidget(key_storage_combo_);
  settings_layout->addWidget(temp_checkbox_);

  auto* actions_layout = new QHBoxLayout();
  encrypt_btn_ = new QPushButton("Encrypt", central);
  decrypt_btn_ = new QPushButton("Decrypt", central);
  terminate_btn_ = new QPushButton("Terminate", central);
  terminate_btn_->setEnabled(false);

  connect(encrypt_btn_, &QPushButton::clicked, this, &MainWindow::onEncrypt);
  connect(decrypt_btn_, &QPushButton::clicked, this, &MainWindow::onDecrypt);
  connect(terminate_btn_, &QPushButton::clicked, this, &MainWindow::onTerminate);

  actions_layout->addWidget(encrypt_btn_);
  actions_layout->addWidget(decrypt_btn_);
  actions_layout->addWidget(terminate_btn_);

  auto* decrypted_box = new QGroupBox("Decrypted (in memory)", central);
  auto* decrypted_layout = new QVBoxLayout(decrypted_box);
  decrypted_list_ = new QListWidget(decrypted_box);
  decrypted_layout->addWidget(decrypted_list_);
  auto* decrypted_actions = new QHBoxLayout();
  preview_btn_ = new QPushButton("Preview", decrypted_box);
  preview_btn_->setEnabled(false);
  connect(preview_btn_, &QPushButton::clicked, this, &MainWindow::onPreviewDecrypted);
  connect(decrypted_list_, &QListWidget::currentRowChanged, this, [this](int row) {
    preview_btn_->setEnabled(row >= 0);
  });
  decrypted_actions->addWidget(preview_btn_);
  decrypted_actions->addStretch();
  decrypted_layout->addLayout(decrypted_actions);

  status_label_ = new QLabel("Ready", central);

  layout->addWidget(files_box);
  layout->addWidget(settings_box);
  layout->addLayout(actions_layout);
  layout->addWidget(decrypted_box);
  layout->addWidget(status_label_);

  setCentralWidget(central);

  guards_ = new SecureGuards(this, static_cast<size_t>(config.clipboard_max_bytes), this);
  connect(guards_, &SecureGuards::violationDetected, this, [this](const QString& reason) {
    addStatus("Violation: " + reason);
    reencryptAll();
    QMessageBox::warning(this, "Security", "Security violation: " + reason);
  });
}

void MainWindow::closeEvent(QCloseEvent* event) {
  if (closing_) {
    event->accept();
    return;
  }

  closing_ = true;
  if (!decrypted_.empty()) {
    if (!reencryptAll()) {
      closing_ = false;
      event->ignore();
      return;
    }
  }

  if (!promptPasswordChange()) {
    closing_ = false;
    event->ignore();
    return;
  }

  event->accept();
}

void MainWindow::onSelectFiles() {
  QStringList files = QFileDialog::getOpenFileNames(this, "Select Files");
  if (files.isEmpty()) return;
  file_list_->clear();
  for (const auto& file : files) {
    if (file.isEmpty()) continue;
    file_list_->addItem(file);
  }
}

void MainWindow::onEncrypt() {
  if (file_list_->count() == 0) {
    addStatus("No files selected");
    return;
  }

  cipheator::Cipher cipher = cipher_from_index(cipher_combo_->currentIndex());
  cipheator::HashAlg hash = hash_from_index(hash_combo_->currentIndex());
  std::string key_storage = (key_storage_combo_->currentIndex() == 0) ? "server" : "client";

  for (int i = 0; i < file_list_->count(); ++i) {
    QString path = file_list_->item(i)->text();
    cipheator::EncryptParams params;
    params.username = username_.toStdString();
    params.password = password_.toStdString();
    params.file_path = path.toStdString();
    params.cipher = cipher;
    params.hash = hash;
    params.key_storage = key_storage;

    cipheator::EncryptResult result;
    if (!client_.encrypt_file(params, &result)) {
      addStatus("Encrypt failed: " + QString::fromStdString(result.message));
      QMessageBox::warning(this, "Encrypt", "Failed: " + QString::fromStdString(result.message));
      continue;
    }
    addStatus("Encrypted: " + path);
  }
}

void MainWindow::onDecrypt() {
  if (file_list_->count() == 0) {
    addStatus("No files selected");
    return;
  }

  for (int i = 0; i < file_list_->count(); ++i) {
    QString path = file_list_->item(i)->text();
    cipheator::DecryptParams params;
    params.username = username_.toStdString();
    params.password = password_.toStdString();
    params.file_path = path.toStdString();

    cipheator::DecryptResult result;
    if (!client_.decrypt_file(params, &result)) {
      addStatus("Decrypt failed: " + QString::fromStdString(result.message));
      QMessageBox::warning(this, "Decrypt", "Failed: " + QString::fromStdString(result.message));
      continue;
    }

    DecryptedItem item;
    item.filePath = path;
    item.data = std::move(result.data);
    item.cipher = result.cipher;
    item.hash = result.hash;
    item.key_storage = result.key_storage;
    item.file_id = result.file_id;
    if (temp_checkbox_ && temp_checkbox_->isChecked()) {
      std::string temp_path = make_temp_path(path);
      std::string temp_err;
      if (write_temp_file(item.data, temp_path, &temp_err)) {
        item.temp_path = temp_path;
      } else {
        addStatus("Temp file failed: " + QString::fromStdString(temp_err));
      }
    }
    decrypted_.push_back(std::move(item));
    auto* list_item = new QListWidgetItem(path, decrypted_list_);
    if (!decrypted_.back().temp_path.empty()) {
      list_item->setToolTip("Temp file: " + QString::fromStdString(decrypted_.back().temp_path));
      addStatus("Decrypted into memory (temp file): " + path);
    } else {
      addStatus("Decrypted into memory: " + path);
    }
  }

  updateSecureState();
}

void MainWindow::onTerminate() {
  if (!reencryptAll()) {
    QMessageBox::warning(this, "Terminate", "Failed to re-encrypt all files");
  }
}

void MainWindow::onPreviewDecrypted() {
  int row = decrypted_list_->currentRow();
  if (row < 0 || static_cast<size_t>(row) >= decrypted_.size()) {
    return;
  }

  const auto& item = decrypted_[static_cast<size_t>(row)];
  const uint8_t* data = item.data.data();
  size_t size = item.data.size();
  size_t show = std::min(size, kPreviewLimit);

  bool binary = looks_binary(data, show);
  QString content;
  if (binary) {
    content = hex_dump(data, show);
  } else {
    content = QString::fromUtf8(reinterpret_cast<const char*>(data),
                                static_cast<int>(show));
  }
  if (size > show) {
    content += "\n\n[Truncated]";
  }

  QDialog dialog(this);
  dialog.setWindowTitle("Preview: " + item.filePath);
  auto* layout = new QVBoxLayout(&dialog);
  auto* view = new QPlainTextEdit(&dialog);
  view->setReadOnly(true);
  view->setPlainText(content);
  layout->addWidget(view);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
  connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  layout->addWidget(buttons);

  dialog.resize(800, 600);
  dialog.exec();
}

bool MainWindow::reencryptAll() {
  if (decrypted_.empty()) {
    updateSecureState();
    return true;
  }

  std::string fallback_key_storage = (key_storage_combo_->currentIndex() == 0) ? "server" : "client";

  for (auto& item : decrypted_) {
    cipheator::EncryptParams params;
    params.username = username_.toStdString();
    params.password = password_.toStdString();
    params.file_path = item.filePath.toStdString();
    params.cipher = item.cipher;
    params.hash = item.hash;
    params.key_storage = item.key_storage.empty() ? fallback_key_storage : item.key_storage;

    std::vector<uint8_t> data(item.data.data(), item.data.data() + item.data.size());

    cipheator::EncryptResult result;
    if (!client_.encrypt_data(params, data, &result, true)) {
      cipheator::secure_zero(data.data(), data.size());
      addStatus("Re-encrypt failed: " + item.filePath);
      return false;
    }
    cipheator::secure_zero(data.data(), data.size());
    if (!item.temp_path.empty()) {
      std::error_code ec;
      std::filesystem::remove(item.temp_path, ec);
    }
    addStatus("Re-encrypted: " + item.filePath);
  }

  decrypted_.clear();
  decrypted_list_->clear();
  updateSecureState();
  return true;
}

bool MainWindow::promptPasswordChange() {
  bool ok = false;
  QString new_password = QInputDialog::getText(this, "Change Password",
                                               "New password:", QLineEdit::Password,
                                               QString(), &ok);
  if (!ok || new_password.isEmpty()) {
    return false;
  }

  QString confirm = QInputDialog::getText(this, "Change Password",
                                          "Confirm new password:", QLineEdit::Password,
                                          QString(), &ok);
  if (!ok || confirm != new_password) {
    QMessageBox::warning(this, "Change Password", "Passwords do not match");
    return false;
  }

  std::string err;
  if (!client_.change_password(username_.toStdString(), password_.toStdString(),
                               new_password.toStdString(), &err)) {
    QMessageBox::warning(this, "Change Password", "Failed: " + QString::fromStdString(err));
    return false;
  }
  password_ = new_password;
  return true;
}

void MainWindow::updateSecureState() {
  bool has_decrypted = !decrypted_.empty();
  terminate_btn_->setEnabled(has_decrypted);
  guards_->setSecureMode(has_decrypted);
  if (preview_btn_) {
    preview_btn_->setEnabled(has_decrypted && decrypted_list_->currentRow() >= 0);
  }
}

void MainWindow::addStatus(const QString& text) {
  status_label_->setText(text);
}
