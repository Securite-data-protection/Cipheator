#include "main_window.h"

#include "secure_guards.h"

#include <algorithm>
#include <QCheckBox>
#include <QAbstractItemView>
#include <QCloseEvent>
#include <QComboBox>
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
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
#include <fstream>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
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

struct RamSessionState {
  std::string dir;
  bool initialized = false;
  bool created = false;
};

RamSessionState& ram_state() {
  static RamSessionState state;
  return state;
}

std::string ram_root_dir() {
  namespace fs = std::filesystem;
  std::error_code ec;
  auto& state = ram_state();
  if (!state.dir.empty()) {
    fs::path p(state.dir);
    if (fs::exists(p, ec) && fs::is_directory(p, ec)) {
      return state.dir;
    }
    return "";
  }
#if !defined(_WIN32)
  fs::path shm("/dev/shm");
  if (fs::exists(shm, ec) && fs::is_directory(shm, ec)) {
    return shm.string();
  }
#endif
  return "";
}

std::string ram_session_dir() {
  auto& state = ram_state();
  if (state.initialized) return state.created ? state.dir : std::string();
  state.initialized = true;

  namespace fs = std::filesystem;
  std::error_code ec;
  fs::path base = ram_root_dir();
  if (base.empty()) {
    state.created = false;
    return "";
  }
#if defined(_WIN32)
  int pid = static_cast<int>(GetCurrentProcessId());
#else
  int pid = static_cast<int>(getpid());
#endif
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  fs::path out = fs::path(base) / ("cipheator_ram_" + std::to_string(pid) + "_" + std::to_string(now));
  fs::create_directories(out, ec);
  state.dir = out.string();
  state.created = !state.dir.empty() && fs::exists(state.dir, ec);
  return state.created ? state.dir : std::string();
}

bool ram_session_created() {
  return ram_state().created;
}

std::string make_temp_path(const QString& original_path) {
  namespace fs = std::filesystem;
  static uint64_t counter = 0;
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  fs::path base = ram_session_dir();
  fs::path name = fs::path(original_path.toStdString()).filename();
  std::string suffix = std::to_string(now) + "_" + std::to_string(counter++);
  fs::path out = base / ("cipheator_tmp_" + suffix + "_" + name.string());
  return out.string();
}

bool secure_wipe_file(const std::string& path) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!fs::exists(path, ec)) return true;
  uintmax_t size = fs::file_size(path, ec);
  if (ec) {
    fs::remove(path, ec);
    return false;
  }

  std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
  if (file) {
    std::vector<char> zeros(8192, 0);
    uintmax_t written = 0;
    while (written < size) {
      size_t chunk = static_cast<size_t>(std::min<uintmax_t>(zeros.size(), size - written));
      file.write(zeros.data(), static_cast<std::streamsize>(chunk));
      if (!file) break;
      written += chunk;
    }
    file.flush();
    file.close();
  }

  fs::remove(path, ec);
  return true;
}

void wipe_ram_session_dir() {
  if (!ram_session_created()) return;
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::path dir(ram_session_dir());
  if (!fs::exists(dir, ec)) return;

  for (auto& entry : fs::directory_iterator(dir, ec)) {
    if (entry.is_regular_file(ec)) {
      secure_wipe_file(entry.path().string());
    } else if (entry.is_directory(ec)) {
      fs::remove_all(entry.path(), ec);
    } else {
      fs::remove(entry.path(), ec);
    }
  }
  fs::remove_all(dir, ec);
  auto& state = ram_state();
  state.dir.clear();
  state.created = false;
  state.initialized = false;
}

bool write_temp_file(const cipheator::SecureBuffer& data,
                     const std::string& path,
                     std::string* err) {
  if (path.empty()) {
    if (err) *err = "RAM-диск не настроен";
    return false;
  }
  std::vector<uint8_t> tmp(data.data(), data.data() + data.size());
  bool ok = cipheator::write_file(path, tmp);
  if (!tmp.empty()) {
    cipheator::secure_zero(tmp.data(), tmp.size());
  }
  if (!ok) {
    if (err) *err = "Failed to write RAM file";
    return false;
  }
#if !defined(_WIN32)
  chmod(path.c_str(), 0600);
#endif
  return true;
}

cipheator::Cipher cipher_from_combo(const QComboBox* combo) {
  if (!combo) return cipheator::Cipher::AES_256_GCM;
  cipheator::Cipher cipher = cipheator::Cipher::AES_256_GCM;
  std::string value = combo->currentData().toString().toStdString();
  if (cipheator::CryptoEngine::cipher_from_string(value, &cipher)) {
    return cipher;
  }
  return cipheator::Cipher::AES_256_GCM;
}

cipheator::HashAlg hash_from_combo(const QComboBox* combo) {
  if (!combo) return cipheator::HashAlg::SHA256;
  cipheator::HashAlg hash = cipheator::HashAlg::SHA256;
  std::string value = combo->currentData().toString().toStdString();
  if (cipheator::CryptoEngine::hash_from_string(value, &hash)) {
    return hash;
  }
  return cipheator::HashAlg::SHA256;
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
      default_key_storage_(config.default_key_storage),
      ram_disk_path_(config.ram_disk_path) {
  if (!ram_disk_path_.empty()) {
    auto& state = ram_state();
    state.dir = ram_disk_path_;
  }
  setWindowTitle("ПАК АС");
  auto* central = new QWidget(this);
  auto* layout = new QVBoxLayout(central);
  layout->setContentsMargins(18, 18, 18, 18);
  layout->setSpacing(14);

  auto* header = new QWidget(central);
  auto* header_layout = new QVBoxLayout(header);
  header_layout->setContentsMargins(0, 0, 0, 0);
  auto* title = new QLabel("Управление конфигурациями шифрования", header);
  title->setObjectName("headerTitle");
  auto* subtitle = new QLabel("Зашифрованные файлы на жестком диске, а расшифрованные в оперативной памяти", header);
  subtitle->setObjectName("headerSub");
  header_layout->addWidget(title);
  header_layout->addWidget(subtitle);
  layout->addWidget(header);

  demo_mode_ = config.demo_mode;
  if (demo_mode_) {
    demo_label_ = new QLabel("ДЕМО-РЕЖИМ", central);
    demo_label_->setStyleSheet("QLabel { color: #b00020; font-weight: bold; }");
    layout->addWidget(demo_label_);
  }

  auto* files_box = new QGroupBox("Выбранные файлы", central);
  auto* files_layout = new QVBoxLayout(files_box);
  file_list_ = new QListWidget(files_box);
  file_list_->setSelectionMode(QAbstractItemView::ExtendedSelection);
  auto* select_btn = new QPushButton("Выбрать файлы", files_box);
  select_btn->setObjectName("secondary");
  connect(select_btn, &QPushButton::clicked, this, &MainWindow::onSelectFiles);
  files_layout->addWidget(file_list_);
  files_layout->addWidget(select_btn);

  auto* encrypt_box = new QGroupBox("Шифрование", central);
  auto* encrypt_layout = new QHBoxLayout(encrypt_box);
  encrypt_layout->setSpacing(12);

  cipher_combo_ = new QComboBox(encrypt_box);
  cipher_combo_->addItem("Кузнечик MGM", "kuznechik");
  cipher_combo_->addItem("AES-GCM", "aes-256-gcm");

  hash_combo_ = new QComboBox(encrypt_box);
  hash_combo_->addItem("SHA-256", "sha256");
  hash_combo_->addItem("SHA-512", "sha512");
  hash_combo_->addItem("SHA3-256", "sha3-256");
  hash_combo_->addItem("SHA3-512", "sha3-512");
  hash_combo_->addItem("BLAKE2b-512", "blake2b-512");
  hash_combo_->addItem("Стрибог-256 (ГОСТ 34.11-2012)", "streebog");

  key_storage_combo_ = new QComboBox(encrypt_box);
  key_storage_combo_->addItem("Сервер (по умолчанию)");
  key_storage_combo_->addItem("Клиент (встроенный ключ)");
  if (default_key_storage_ == "client") {
    key_storage_combo_->setCurrentIndex(1);
  }

  encrypt_layout->addWidget(new QLabel("Алгоритм:", encrypt_box));
  encrypt_layout->addWidget(cipher_combo_);
  encrypt_layout->addWidget(new QLabel("Хэш:", encrypt_box));
  encrypt_layout->addWidget(hash_combo_);
  encrypt_layout->addWidget(new QLabel("Хранение ключа:", encrypt_box));
  encrypt_layout->addWidget(key_storage_combo_);

  auto* decrypt_box = new QGroupBox("Расшифрование", central);
  auto* decrypt_layout = new QHBoxLayout(decrypt_box);
  decrypt_layout->setSpacing(12);
  temp_checkbox_ = new QCheckBox("Расшифровывать в RAM-диск (авто-очистка)", decrypt_box);
  temp_checkbox_->setChecked(config.decrypt_to_temp);
  connect(temp_checkbox_, &QCheckBox::toggled, this, [this](bool) {
    updateDecryptedActions();
  });
  decrypt_layout->addWidget(temp_checkbox_);
  if (ram_root_dir().empty()) {
    temp_checkbox_->setChecked(false);
    temp_checkbox_->setEnabled(false);
    temp_checkbox_->setToolTip("RAM-диск не настроен. Укажите ram_disk_path в config/client.conf.");
  }

  auto* actions_layout = new QHBoxLayout();
  actions_layout->setSpacing(12);
  encrypt_btn_ = new QPushButton("Зашифровать", central);
  decrypt_btn_ = new QPushButton("Расшифровать", central);
  terminate_btn_ = new QPushButton("Очистить", central);
  terminate_btn_->setEnabled(false);
  terminate_btn_->setObjectName("danger");

  connect(encrypt_btn_, &QPushButton::clicked, this, &MainWindow::onEncrypt);
  connect(decrypt_btn_, &QPushButton::clicked, this, &MainWindow::onDecrypt);
  connect(terminate_btn_, &QPushButton::clicked, this, &MainWindow::onTerminate);

  actions_layout->addWidget(encrypt_btn_);
  actions_layout->addWidget(decrypt_btn_);
  actions_layout->addWidget(terminate_btn_);

  auto* decrypted_box = new QGroupBox("Расшифрованные файлы в ОП", central);
  auto* decrypted_layout = new QVBoxLayout(decrypted_box);
  decrypted_list_ = new QListWidget(decrypted_box);
  decrypted_layout->addWidget(decrypted_list_);
  auto* decrypted_actions = new QHBoxLayout();
  decrypted_actions->setSpacing(12);
  preview_btn_ = new QPushButton("Просмотр", decrypted_box);
  preview_btn_->setEnabled(false);
  preview_btn_->setObjectName("secondary");
  copy_temp_btn_ = new QPushButton("Копировать путь", decrypted_box);
  copy_temp_btn_->setEnabled(false);
  copy_temp_btn_->setObjectName("secondary");
  connect(preview_btn_, &QPushButton::clicked, this, &MainWindow::onPreviewDecrypted);
  connect(copy_temp_btn_, &QPushButton::clicked, this, &MainWindow::onCopyTempPath);
  connect(decrypted_list_, &QListWidget::currentRowChanged, this, [this](int) {
    updateDecryptedActions();
  });
  decrypted_actions->addWidget(preview_btn_);
  decrypted_actions->addWidget(copy_temp_btn_);
  decrypted_actions->addStretch();
  decrypted_layout->addLayout(decrypted_actions);

  status_label_ = new QLabel("Готово", central);
  status_label_->setVisible(false);

  layout->addWidget(files_box);
  layout->addWidget(encrypt_box);
  layout->addWidget(decrypt_box);
  layout->addLayout(actions_layout);
  layout->addWidget(decrypted_box);
  // status_label_ hidden for cleaner UI

  setCentralWidget(central);

  guards_ = new SecureGuards(this, static_cast<size_t>(config.clipboard_max_bytes), this);
  connect(guards_, &SecureGuards::violationDetected, this, [this](const QString& reason) {
    addStatus("Нарушение: " + reason);
    reencryptAll();
    QMessageBox::warning(this, "Безопасность", "Нарушение безопасности: " + reason);
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

  if (password_expired_) {
    if (!promptPasswordChangeUnified()) {
      closing_ = false;
      event->ignore();
      return;
    }
  }

  wipe_ram_session_dir();
  event->accept();
}

void MainWindow::onSelectFiles() {
  QStringList files = QFileDialog::getOpenFileNames(this, "Выберите файлы");
  if (files.isEmpty()) return;
  file_list_->clear();
  for (const auto& file : files) {
    if (file.isEmpty()) continue;
    file_list_->addItem(file);
  }
}

void MainWindow::onEncrypt() {
  if (file_list_->count() == 0) {
    addStatus("Файлы не выбраны");
    return;
  }

  cipheator::Cipher cipher = cipher_from_combo(cipher_combo_);
  cipheator::HashAlg hash = hash_from_combo(hash_combo_);
  std::string key_storage = (key_storage_combo_->currentIndex() == 0) ? "server" : "client";

  QStringList targets = selectedFilePaths();
  for (const auto& path : targets) {
    cipheator::EncryptParams params;
    params.username = username_.toStdString();
    params.password = password_.toStdString();
    params.file_path = path.toStdString();
    params.cipher = cipher;
    params.hash = hash;
    params.key_storage = key_storage;

    cipheator::EncryptResult result;
    if (!client_.encrypt_file(params, &result)) {
      addStatus("Ошибка шифрования: " + QString::fromStdString(result.message));
      QMessageBox::warning(this, "Шифрование", "Ошибка: " + QString::fromStdString(result.message));
      if (result.error_code == "password_expired") {
        password_expired_ = true;
        if (promptPasswordChangeUnified()) {
          password_expired_ = false;
        }
      }
      registerAuthFailure(result.error_code);
      continue;
    }
    auth_failures_ = 0;
    addStatus("Зашифровано: " + path);
    QMessageBox::information(this, "Шифрование",
                             "Файл успешно зашифрован:\n" + path);
  }
}

void MainWindow::onDecrypt() {
  if (file_list_->count() == 0) {
    addStatus("Файлы не выбраны");
    return;
  }

  QStringList targets = selectedFilePaths();
  for (const auto& path : targets) {
    cipheator::DecryptParams params;
    params.username = username_.toStdString();
    params.password = password_.toStdString();
    params.file_path = path.toStdString();

    cipheator::DecryptResult result;
    if (!client_.decrypt_file(params, &result)) {
      addStatus("Ошибка расшифрования: " + QString::fromStdString(result.message));
      QMessageBox::warning(this, "Расшифрование", "Ошибка: " + QString::fromStdString(result.message));
      if (result.error_code == "password_expired") {
        password_expired_ = true;
        if (promptPasswordChangeUnified()) {
          password_expired_ = false;
        }
      }
      registerAuthFailure(result.error_code);
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
        addStatus("Ошибка RAM-диска: " + QString::fromStdString(temp_err));
      }
    }
    decrypted_.push_back(std::move(item));
    auto* list_item = new QListWidgetItem(path, decrypted_list_);
    if (!decrypted_.back().temp_path.empty()) {
      list_item->setToolTip("RAM-диск: " + QString::fromStdString(decrypted_.back().temp_path));
      addStatus("Расшифровано в RAM-диск: " + path);
    } else {
      addStatus("Расшифровано в память: " + path);
    }
  }

  auth_failures_ = 0;
  updateSecureState();
}

void MainWindow::onTerminate() {
  if (!reencryptAll()) {
    QMessageBox::warning(this, "Очистка", "Не удалось очистить и пере-зашифровать файлы");
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
    content += "\n\n[Обрезано]";
  }

  QDialog dialog(this);
  dialog.setWindowTitle("Просмотр: " + item.filePath);
  auto* layout = new QVBoxLayout(&dialog);
  auto* view = new QPlainTextEdit(&dialog);
  view->setStyleSheet(
      "QPlainTextEdit {"
      " background: #ffffff;"
      " color: #1f2937;"
      " border: 1px solid #d7dee7;"
      " border-radius: 6px;"
      " selection-background-color: #0f5f5f;"
      " selection-color: #ffffff;"
      "}"
  );
  view->setReadOnly(true);
  view->setPlainText(content);
  layout->addWidget(view);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
  if (auto* close_btn = buttons->button(QDialogButtonBox::Close)) {
    close_btn->setText("Закрыть");
  }
  connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  layout->addWidget(buttons);

  dialog.resize(800, 600);
  dialog.exec();
}

void MainWindow::onCopyTempPath() {
  int row = decrypted_list_->currentRow();
  if (row < 0 || static_cast<size_t>(row) >= decrypted_.size()) {
    return;
  }
  const auto& item = decrypted_[static_cast<size_t>(row)];
  if (item.temp_path.empty()) {
    QMessageBox::information(this, "RAM-диск", "Для этого файла нет пути в RAM-диск.");
    return;
  }
  if (auto* clipboard = QApplication::clipboard()) {
    clipboard->setText(QString::fromStdString(item.temp_path));
  }
  QMessageBox::information(this, "RAM-диск", "Путь скопирован в буфер обмена.");
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
      secure_wipe_file(item.temp_path);
    }
    addStatus("Re-encrypted: " + item.filePath);
  }

  decrypted_.clear();
  decrypted_list_->clear();
  wipe_ram_session_dir();
  updateSecureState();
  return true;
}

bool MainWindow::promptPasswordChange() {
  bool ok = false;
  QString new_password = QInputDialog::getText(this, "Смена пароля",
                                               "Новый пароль:", QLineEdit::Password,
                                               QString(), &ok);
  if (!ok || new_password.isEmpty()) {
    return false;
  }

  QString confirm = QInputDialog::getText(this, "Смена пароля",
                                          "Подтвердите пароль:", QLineEdit::Password,
                                          QString(), &ok);
  if (!ok || confirm != new_password) {
    QMessageBox::warning(this, "Смена пароля", "Пароли не совпадают");
    return false;
  }

  std::string err;
  if (!client_.change_password(username_.toStdString(), password_.toStdString(),
                               new_password.toStdString(), &err)) {
    QMessageBox::warning(this, "Смена пароля", "Ошибка: " + QString::fromStdString(err));
    return false;
  }
  password_ = new_password;
  return true;
}

bool MainWindow::promptPasswordChangeUnified() {
  QDialog dialog(this);
  dialog.setWindowTitle("Смена пароля");
  dialog.setMinimumWidth(500);
  auto* layout = new QVBoxLayout(&dialog);
  auto* form = new QFormLayout();
  form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
  form->setHorizontalSpacing(14);
  form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

  auto* new_pass = new QLineEdit(&dialog);
  auto* confirm = new QLineEdit(&dialog);
  new_pass->setEchoMode(QLineEdit::Password);
  confirm->setEchoMode(QLineEdit::Password);

  auto* new_pass_label = new QLabel("Новый пароль:", &dialog);
  auto* confirm_label = new QLabel("Подтверждение:", &dialog);
  new_pass_label->setMinimumWidth(140);
  confirm_label->setMinimumWidth(140);
  form->addRow(new_pass_label, new_pass);
  form->addRow(confirm_label, confirm);
  layout->addLayout(form);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  if (auto* ok_btn = buttons->button(QDialogButtonBox::Ok)) {
    ok_btn->setText("ОК");
  }
  if (auto* cancel_btn = buttons->button(QDialogButtonBox::Cancel)) {
    cancel_btn->setText("Отмена");
  }
  connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  layout->addWidget(buttons);

  if (dialog.exec() != QDialog::Accepted) {
    return false;
  }

  if (new_pass->text().isEmpty()) {
    QMessageBox::warning(this, "Смена пароля", "Пароль не может быть пустым");
    return false;
  }
  if (new_pass->text() != confirm->text()) {
    QMessageBox::warning(this, "Смена пароля", "Пароли не совпадают");
    return false;
  }

  std::string err;
  if (!client_.change_password(username_.toStdString(), password_.toStdString(),
                               new_pass->text().toStdString(), &err)) {
    QMessageBox::warning(this, "Смена пароля", "Ошибка: " + QString::fromStdString(err));
    return false;
  }
  password_ = new_pass->text();
  auth_failures_ = 0;
  password_expired_ = false;
  return true;
}

void MainWindow::updateSecureState() {
  bool has_decrypted = !decrypted_.empty();
  terminate_btn_->setEnabled(has_decrypted);
  guards_->setSecureMode(has_decrypted);
  updateDecryptedActions();
}

void MainWindow::addStatus(const QString& text) {
  if (status_label_) {
    status_label_->setText(text);
  }
}

void MainWindow::registerAuthFailure(const std::string& code) {
  if (code != "auth_failed") return;
  auth_failures_ += 1;
  if (auth_failures_ >= 5) {
    clearSessionKey();
  }
  if (auth_failures_ >= 3) {
    reencryptAll();
    QMessageBox::critical(this, "Безопасность",
                          "АРМ заблокирован до перезапуска устройства.");
    QApplication::quit();
  }
}

void MainWindow::clearSessionKey() {
  if (!password_.isEmpty()) {
    cipheator::secure_zero(password_.data(), static_cast<size_t>(password_.size()) * sizeof(QChar));
  }
  password_.clear();
}

QStringList MainWindow::selectedFilePaths() const {
  QStringList out;
  if (!file_list_) return out;
  const auto items = file_list_->selectedItems();
  if (!items.isEmpty()) {
    for (const auto* item : items) {
      if (item) out << item->text();
    }
    return out;
  }
  for (int i = 0; i < file_list_->count(); ++i) {
    if (auto* item = file_list_->item(i)) {
      out << item->text();
    }
  }
  return out;
}

void MainWindow::updateDecryptedActions() {
  int row = decrypted_list_ ? decrypted_list_->currentRow() : -1;
  bool has_row = row >= 0 && static_cast<size_t>(row) < decrypted_.size();
  if (preview_btn_) {
    preview_btn_->setEnabled(has_row);
  }
  if (copy_temp_btn_) {
    bool show = temp_checkbox_ && temp_checkbox_->isChecked();
    copy_temp_btn_->setVisible(show);
    bool has_temp = show && has_row && !decrypted_[static_cast<size_t>(row)].temp_path.empty();
    copy_temp_btn_->setEnabled(has_temp);
  }
}
