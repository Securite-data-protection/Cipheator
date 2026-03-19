#pragma once

#include "admin_client.h"

#include <QMainWindow>
#include <QTimer>

#include <unordered_map>
#include <vector>

class QListWidget;
class QPlainTextEdit;
class QLabel;

class AdminWindow : public QMainWindow {
  Q_OBJECT
 public:
  explicit AdminWindow(const cipheator::AdminConfig& config, QWidget* parent = nullptr);

 private slots:
  void onAddDevice();
  void onRemoveDevice();
  void onRefreshAlerts();
  void onRefreshLogs();
  void onRefreshStats();
  void onRefreshBinding();
  void onToggleBinding();
  void onAllowClient();
  void onBlockClient();
  void onUnlockUser();
  void onAutoRefresh();

 private:
  void loadDevices();
  void saveDevices();
  void updateDeviceList();
  cipheator::AdminDevice* selectedDevice();
  std::string deviceKey(const cipheator::AdminDevice& device) const;
  void addStatus(const QString& text);
  void renderPatternAnalysis(const std::vector<std::string>& logs,
                             const std::vector<std::string>& stats,
                             const std::vector<std::string>& locks,
                             const cipheator::AdminDevice& device);

  cipheator::AdminClient client_;
  std::vector<cipheator::AdminDevice> devices_;
  std::unordered_map<std::string, uint64_t> last_alert_ids_;
  std::unordered_map<std::string, std::vector<std::string>> cached_clients_;
  std::unordered_map<std::string, std::vector<std::string>> cached_logs_;
  std::unordered_map<std::string, std::vector<std::string>> cached_stats_;
  std::unordered_map<std::string, std::vector<std::string>> cached_locks_;
  std::unordered_map<std::string, bool> cached_binding_enabled_;

  QListWidget* device_list_ = nullptr;
  QListWidget* alert_list_ = nullptr;
  QPlainTextEdit* log_view_ = nullptr;
  QPlainTextEdit* stats_view_ = nullptr;
  QPlainTextEdit* binding_view_ = nullptr;
  QPlainTextEdit* analysis_view_ = nullptr;
  QLabel* status_label_ = nullptr;
  QTimer auto_timer_;
};
