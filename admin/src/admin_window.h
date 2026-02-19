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
  void onAutoRefresh();

 private:
  void loadDevices();
  void saveDevices();
  void updateDeviceList();
  cipheator::AdminDevice* selectedDevice();
  std::string deviceKey(const cipheator::AdminDevice& device) const;
  void addStatus(const QString& text);

  cipheator::AdminClient client_;
  std::vector<cipheator::AdminDevice> devices_;
  std::unordered_map<std::string, uint64_t> last_alert_ids_;

  QListWidget* device_list_ = nullptr;
  QListWidget* alert_list_ = nullptr;
  QPlainTextEdit* log_view_ = nullptr;
  QPlainTextEdit* stats_view_ = nullptr;
  QLabel* status_label_ = nullptr;
  QTimer auto_timer_;
};
