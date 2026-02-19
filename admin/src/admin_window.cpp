#include "admin_window.h"

#include <QAction>
#include <QFormLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

#include <fstream>
#include <string>

namespace {

const char* kDevicesPath = "config/admin_devices.conf";

} // namespace

AdminWindow::AdminWindow(const cipheator::AdminConfig& config, QWidget* parent)
    : QMainWindow(parent), client_(config) {
  setWindowTitle("Cipheator Admin");

  auto* central = new QWidget(this);
  auto* layout = new QVBoxLayout(central);

  auto* splitter = new QSplitter(Qt::Horizontal, central);

  device_list_ = new QListWidget(splitter);
  alert_list_ = new QListWidget(splitter);

  auto* right_pane = new QWidget(splitter);
  auto* right_layout = new QVBoxLayout(right_pane);

  log_view_ = new QPlainTextEdit(right_pane);
  log_view_->setReadOnly(true);
  stats_view_ = new QPlainTextEdit(right_pane);
  stats_view_->setReadOnly(true);

  right_layout->addWidget(new QLabel("Logs", right_pane));
  right_layout->addWidget(log_view_);
  right_layout->addWidget(new QLabel("User Stats", right_pane));
  right_layout->addWidget(stats_view_);

  splitter->addWidget(device_list_);
  splitter->addWidget(alert_list_);
  splitter->addWidget(right_pane);
  splitter->setStretchFactor(2, 1);

  status_label_ = new QLabel("Ready", central);

  layout->addWidget(splitter);
  layout->addWidget(status_label_);
  setCentralWidget(central);

  auto* toolbar = addToolBar("Actions");
  QAction* add_action = toolbar->addAction("Add Device");
  QAction* remove_action = toolbar->addAction("Remove Device");
  QAction* alerts_action = toolbar->addAction("Refresh Alerts");
  QAction* logs_action = toolbar->addAction("Refresh Logs");
  QAction* stats_action = toolbar->addAction("Refresh Stats");

  connect(add_action, &QAction::triggered, this, &AdminWindow::onAddDevice);
  connect(remove_action, &QAction::triggered, this, &AdminWindow::onRemoveDevice);
  connect(alerts_action, &QAction::triggered, this, &AdminWindow::onRefreshAlerts);
  connect(logs_action, &QAction::triggered, this, &AdminWindow::onRefreshLogs);
  connect(stats_action, &QAction::triggered, this, &AdminWindow::onRefreshStats);

  auto_timer_.setInterval(30000);
  connect(&auto_timer_, &QTimer::timeout, this, &AdminWindow::onAutoRefresh);
  auto_timer_.start();

  loadDevices();
  updateDeviceList();
}

void AdminWindow::loadDevices() {
  devices_.clear();
  std::ifstream in(kDevicesPath);
  if (!in) return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    size_t p1 = line.find('|');
    size_t p2 = line.find('|', p1 + 1);
    size_t p3 = line.find('|', p2 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) {
      continue;
    }
    cipheator::AdminDevice d;
    d.name = line.substr(0, p1);
    d.host = line.substr(p1 + 1, p2 - p1 - 1);
    try {
      d.port = std::stoi(line.substr(p2 + 1, p3 - p2 - 1));
    } catch (...) {
      d.port = 7444;
    }
    d.token = line.substr(p3 + 1);
    devices_.push_back(d);
  }
}

void AdminWindow::saveDevices() {
  std::ofstream out(kDevicesPath, std::ios::trunc);
  if (!out) return;
  for (const auto& d : devices_) {
    out << d.name << "|" << d.host << "|" << d.port << "|" << d.token << "\n";
  }
}

void AdminWindow::updateDeviceList() {
  device_list_->clear();
  for (const auto& d : devices_) {
    device_list_->addItem(QString::fromStdString(d.name + " (" + d.host + ":" + std::to_string(d.port) + ")"));
  }
}

cipheator::AdminDevice* AdminWindow::selectedDevice() {
  int row = device_list_->currentRow();
  if (row < 0 || static_cast<size_t>(row) >= devices_.size()) return nullptr;
  return &devices_[static_cast<size_t>(row)];
}

std::string AdminWindow::deviceKey(const cipheator::AdminDevice& device) const {
  return device.host + ":" + std::to_string(device.port);
}

void AdminWindow::onAddDevice() {
  bool ok = false;
  QString name = QInputDialog::getText(this, "Add Device", "Name:", QLineEdit::Normal, "", &ok);
  if (!ok || name.isEmpty()) return;
  QString host = QInputDialog::getText(this, "Add Device", "Host:", QLineEdit::Normal, "127.0.0.1", &ok);
  if (!ok || host.isEmpty()) return;
  int port = QInputDialog::getInt(this, "Add Device", "Port:", 7444, 1, 65535, 1, &ok);
  if (!ok) return;
  QString token = QInputDialog::getText(this, "Add Device", "Admin token:", QLineEdit::Password, "", &ok);
  if (!ok || token.isEmpty()) return;

  cipheator::AdminDevice d;
  d.name = name.toStdString();
  d.host = host.toStdString();
  d.port = port;
  d.token = token.toStdString();
  devices_.push_back(d);
  saveDevices();
  updateDeviceList();
  addStatus("Device added");
}

void AdminWindow::onRemoveDevice() {
  int row = device_list_->currentRow();
  if (row < 0 || static_cast<size_t>(row) >= devices_.size()) return;
  devices_.erase(devices_.begin() + row);
  saveDevices();
  updateDeviceList();
  addStatus("Device removed");
}

void AdminWindow::onRefreshAlerts() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Select a device");
    return;
  }
  std::string key = deviceKey(*device);
  uint64_t since_id = 0;
  auto it = last_alert_ids_.find(key);
  if (it != last_alert_ids_.end()) since_id = it->second;

  std::vector<std::string> lines;
  uint64_t last_id = since_id;
  std::string err;
  if (!client_.get_alerts(*device, since_id, 200, &lines, &last_id, &err)) {
    addStatus(QString::fromStdString("Alerts error: " + err));
    return;
  }

  if (last_id > since_id) {
    last_alert_ids_[key] = last_id;
  }

  for (const auto& line : lines) {
    alert_list_->addItem(QString::fromStdString(line));
  }

  if (!lines.empty()) {
    QMessageBox::information(this, "Alerts", "New alerts received: " + QString::number(lines.size()));
  }
  addStatus("Alerts refreshed");
}

void AdminWindow::onRefreshLogs() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Select a device");
    return;
  }

  std::vector<std::string> lines;
  std::string err;
  if (!client_.get_logs(*device, 200, &lines, &err)) {
    addStatus(QString::fromStdString("Logs error: " + err));
    return;
  }

  QString text;
  for (const auto& line : lines) {
    text += QString::fromStdString(line);
    text += "\n";
  }
  log_view_->setPlainText(text);
  addStatus("Logs refreshed");
}

void AdminWindow::onRefreshStats() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Select a device");
    return;
  }

  std::vector<std::string> lines;
  std::string err;
  if (!client_.get_stats(*device, 200, &lines, &err)) {
    addStatus(QString::fromStdString("Stats error: " + err));
    return;
  }

  QString text;
  for (const auto& line : lines) {
    text += QString::fromStdString(line);
    text += "\n";
  }
  stats_view_->setPlainText(text);
  addStatus("Stats refreshed");
}

void AdminWindow::onAutoRefresh() {
  onRefreshAlerts();
}

void AdminWindow::addStatus(const QString& text) {
  status_label_->setText(text);
}
