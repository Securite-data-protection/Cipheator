#pragma once

#include <QMainWindow>
#include <vector>

#include "client_core.h"

class QListWidget;
class QComboBox;
class QCheckBox;
class QPushButton;
class QLabel;

class SecureGuards;

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:
  MainWindow(const cipheator::ClientConfig& config,
             const QString& username,
             const QString& password,
             QWidget* parent = nullptr);

 protected:
  void closeEvent(QCloseEvent* event) override;

 private slots:
  void onSelectFiles();
  void onEncrypt();
  void onDecrypt();
  void onTerminate();
  void onPreviewDecrypted();
  void onCopyTempPath();

 private:
  struct DecryptedItem {
    QString filePath;
    cipheator::SecureBuffer data;
    cipheator::Cipher cipher = cipheator::Cipher::AES_256_GCM;
    cipheator::HashAlg hash = cipheator::HashAlg::SHA256;
    std::string key_storage;
    std::string file_id;
    std::string temp_path;
  };

  bool reencryptAll();
  bool promptPasswordChange();
  bool promptPasswordChangeUnified();
  void updateSecureState();
  void addStatus(const QString& text);
  QStringList selectedFilePaths() const;
  void updateDecryptedActions();
  void registerAuthFailure(const std::string& code);
  void clearSessionKey();

  cipheator::ClientCore client_;
  QString username_;
  QString password_;
  std::string default_key_storage_;
  bool demo_mode_ = false;
  int auth_failures_ = 0;
  bool password_expired_ = false;

  QListWidget* file_list_ = nullptr;
  QListWidget* decrypted_list_ = nullptr;
  QComboBox* cipher_combo_ = nullptr;
  QComboBox* hash_combo_ = nullptr;
  QComboBox* key_storage_combo_ = nullptr;
  QCheckBox* temp_checkbox_ = nullptr;
  QLabel* demo_label_ = nullptr;
  QPushButton* copy_temp_btn_ = nullptr;
  QPushButton* encrypt_btn_ = nullptr;
  QPushButton* decrypt_btn_ = nullptr;
  QPushButton* terminate_btn_ = nullptr;
  QPushButton* preview_btn_ = nullptr;
  QLabel* status_label_ = nullptr;

  std::vector<DecryptedItem> decrypted_;
  SecureGuards* guards_ = nullptr;
  bool closing_ = false;
};
