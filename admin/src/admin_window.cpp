#include "admin_window.h"

#include <QAction>
#include <QDateTime>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

namespace {

const char* kDevicesPath = "config/admin_devices.conf";

struct PatternStat {
  size_t requests = 0;
  size_t auth_failed = 0;
  uint64_t bytes_in = 0;
  uint64_t bytes_out = 0;
  uint64_t max_single = 0;
  uint32_t total_logins = 0;
  bool locked = false;
  int64_t lock_remaining = 0;
};

std::vector<std::string> split_pipe(const std::string& line) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= line.size()) {
    size_t pos = line.find('|', start);
    if (pos == std::string::npos) {
      out.push_back(line.substr(start));
      break;
    }
    out.push_back(line.substr(start, pos - start));
    start = pos + 1;
  }
  return out;
}

uint64_t extract_uint(const std::string& text, const std::string& key) {
  size_t pos = text.find(key);
  if (pos == std::string::npos) return 0;
  pos += key.size();
  size_t end = pos;
  while (end < text.size() && std::isdigit(static_cast<unsigned char>(text[end]))) {
    ++end;
  }
  if (end == pos) return 0;
  try {
    return static_cast<uint64_t>(std::stoull(text.substr(pos, end - pos)));
  } catch (...) {
    return 0;
  }
}

QString bytes_to_mb(uint64_t bytes) {
  double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
  return QString::number(mb, 'f', 1) + " MB";
}

} // namespace

AdminWindow::AdminWindow(const cipheator::AdminConfig& config, QWidget* parent)
    : QMainWindow(parent), client_(config) {
  setWindowTitle("Админ-панель");

  auto* central = new QWidget(this);
  auto* layout = new QVBoxLayout(central);

  auto* splitter = new QSplitter(Qt::Horizontal, central);
  device_list_ = new QListWidget(splitter);
  alert_list_ = new QListWidget(splitter);

  auto* right_pane = new QWidget(splitter);
  auto* right_layout = new QVBoxLayout(right_pane);

  binding_view_ = new QPlainTextEdit(right_pane);
  binding_view_->setReadOnly(true);
  log_view_ = new QPlainTextEdit(right_pane);
  log_view_->setReadOnly(true);
  stats_view_ = new QPlainTextEdit(right_pane);
  stats_view_->setReadOnly(true);
  analysis_view_ = new QPlainTextEdit(right_pane);
  analysis_view_->setReadOnly(true);

  right_layout->addWidget(new QLabel("Жесткая привязка ПК", right_pane));
  right_layout->addWidget(binding_view_);
  right_layout->addWidget(new QLabel("Журналы", right_pane));
  right_layout->addWidget(log_view_);
  right_layout->addWidget(new QLabel("Статистика пользователей", right_pane));
  right_layout->addWidget(stats_view_);
  right_layout->addWidget(new QLabel("Анализ поведения", right_pane));
  right_layout->addWidget(analysis_view_);

  splitter->addWidget(device_list_);
  splitter->addWidget(alert_list_);
  splitter->addWidget(right_pane);
  splitter->setStretchFactor(2, 1);

  status_label_ = new QLabel("Готово", central);

  layout->addWidget(splitter);
  layout->addWidget(status_label_);
  setCentralWidget(central);

  auto* toolbar = addToolBar("Действия");
  QAction* add_action = toolbar->addAction("Добавить устройство");
  QAction* remove_action = toolbar->addAction("Удалить устройство");
  QAction* alerts_action = toolbar->addAction("Обновить тревоги");
  QAction* logs_action = toolbar->addAction("Обновить журнал");
  QAction* stats_action = toolbar->addAction("Обновить статистику");
  QAction* binding_action = toolbar->addAction("Обновить привязку");
  QAction* toggle_binding_action = toolbar->addAction("Вкл/Выкл привязку");
  QAction* allow_client_action = toolbar->addAction("Разрешить ПК");
  QAction* block_client_action = toolbar->addAction("Заблокировать ПК");
  QAction* unlock_user_action = toolbar->addAction("Снять блокировку");

  connect(add_action, &QAction::triggered, this, &AdminWindow::onAddDevice);
  connect(remove_action, &QAction::triggered, this, &AdminWindow::onRemoveDevice);
  connect(alerts_action, &QAction::triggered, this, &AdminWindow::onRefreshAlerts);
  connect(logs_action, &QAction::triggered, this, &AdminWindow::onRefreshLogs);
  connect(stats_action, &QAction::triggered, this, &AdminWindow::onRefreshStats);
  connect(binding_action, &QAction::triggered, this, &AdminWindow::onRefreshBinding);
  connect(toggle_binding_action, &QAction::triggered, this, &AdminWindow::onToggleBinding);
  connect(allow_client_action, &QAction::triggered, this, &AdminWindow::onAllowClient);
  connect(block_client_action, &QAction::triggered, this, &AdminWindow::onBlockClient);
  connect(unlock_user_action, &QAction::triggered, this, &AdminWindow::onUnlockUser);

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
  QString name = QInputDialog::getText(this, "Добавить устройство", "Имя:", QLineEdit::Normal, "", &ok);
  if (!ok || name.isEmpty()) return;
  QString host = QInputDialog::getText(this, "Добавить устройство", "Хост:", QLineEdit::Normal, "127.0.0.1", &ok);
  if (!ok || host.isEmpty()) return;
  int port = QInputDialog::getInt(this, "Добавить устройство", "Порт:", 7443, 1, 65535, 1, &ok);
  if (!ok) return;
  QString token = QInputDialog::getText(this, "Добавить устройство", "Админ-токен:", QLineEdit::Normal, "", &ok);
  if (!ok || token.isEmpty()) return;

  cipheator::AdminDevice d;
  d.name = name.toStdString();
  d.host = host.toStdString();
  d.port = port;
  d.token = token.toStdString();
  devices_.push_back(d);
  saveDevices();
  updateDeviceList();
  addStatus("Устройство добавлено");
}

void AdminWindow::onRemoveDevice() {
  int row = device_list_->currentRow();
  if (row < 0 || static_cast<size_t>(row) >= devices_.size()) return;
  devices_.erase(devices_.begin() + row);
  saveDevices();
  updateDeviceList();
  addStatus("Устройство удалено");
}

void AdminWindow::onRefreshAlerts() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
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
    addStatus(QString::fromStdString("Ошибка тревог: " + err));
    return;
  }

  if (last_id > since_id) {
    last_alert_ids_[key] = last_id;
  }

  for (const auto& line : lines) {
    alert_list_->addItem(QString::fromStdString(line));
  }

  addStatus("Тревоги обновлены");
}

void AdminWindow::onRefreshLogs() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }

  std::vector<std::string> lines;
  std::string err;
  if (!client_.get_logs(*device, 200, &lines, &err)) {
    addStatus(QString::fromStdString("Ошибка журнала: " + err));
    return;
  }

  QString text;
  for (const auto& line : lines) {
    text += QString::fromStdString(line);
    text += "\n";
  }
  log_view_->setPlainText(text);

  const std::string key = deviceKey(*device);
  cached_logs_[key] = lines;
  renderPatternAnalysis(cached_logs_[key], cached_stats_[key], cached_locks_[key], *device);
  addStatus("Журнал обновлён");
}

void AdminWindow::onRefreshStats() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }

  std::vector<std::string> lines;
  std::string err;
  if (!client_.get_stats(*device, 200, &lines, &err)) {
    addStatus(QString::fromStdString("Ошибка статистики: " + err));
    return;
  }

  QString text;
  for (const auto& line : lines) {
    text += QString::fromStdString(line);
    text += "\n";
  }
  stats_view_->setPlainText(text);

  std::vector<std::string> locks;
  if (!client_.get_locks(*device, 200, &locks, &err)) {
    locks.clear();
  }

  const std::string key = deviceKey(*device);
  cached_stats_[key] = lines;
  cached_locks_[key] = locks;
  renderPatternAnalysis(cached_logs_[key], cached_stats_[key], cached_locks_[key], *device);
  addStatus("Статистика обновлена");
}

void AdminWindow::onRefreshBinding() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }
  bool enabled = false;
  std::vector<std::string> lines;
  std::string err;
  if (!client_.get_binding(*device, 500, &enabled, &lines, &err)) {
    addStatus(QString::fromStdString("Ошибка привязки: " + err));
    return;
  }

  QString text;
  text += QString("Привязка клиентов: %1\n\n").arg(enabled ? "ВКЛ" : "ВЫКЛ");
  for (const auto& line : lines) {
    auto p = split_pipe(line);
    if (p.size() < 5) {
      text += QString::fromStdString(line) + "\n";
      continue;
    }
    text += QString::fromStdString(p[0]) + " | " + (p[1] == "1" ? "разрешен" : "заблокирован") +
            " | first=" + QString::fromStdString(p[2]) +
            " | last=" + QString::fromStdString(p[3]) +
            " | " + QString::fromStdString(p[4]) + "\n";
  }
  binding_view_->setPlainText(text);

  const std::string key = deviceKey(*device);
  cached_clients_[key] = lines;
  cached_binding_enabled_[key] = enabled;
  addStatus("Политика привязки обновлена");
}

void AdminWindow::onToggleBinding() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }

  const std::string key = deviceKey(*device);
  bool enabled = false;
  auto it = cached_binding_enabled_.find(key);
  if (it != cached_binding_enabled_.end()) {
    enabled = it->second;
  } else {
    std::vector<std::string> tmp;
    std::string err;
    if (!client_.get_binding(*device, 10, &enabled, &tmp, &err)) {
      addStatus(QString::fromStdString("Ошибка получения статуса привязки: " + err));
      return;
    }
  }

  bool target = !enabled;
  std::string err;
  if (!client_.set_binding(*device, target, &err)) {
    addStatus(QString::fromStdString("Ошибка переключения привязки: " + err));
    return;
  }

  onRefreshBinding();
  addStatus(target ? "Привязка включена" : "Привязка выключена");
}

void AdminWindow::onAllowClient() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }

  bool ok = false;
  QString client_id = QInputDialog::getText(this,
                                            "Разрешить ПК",
                                            "Client ID:",
                                            QLineEdit::Normal,
                                            "",
                                            &ok);
  if (!ok || client_id.isEmpty()) return;

  std::string err;
  if (!client_.set_client_allowed(*device, client_id.toStdString(), true, &err)) {
    addStatus(QString::fromStdString("Ошибка разрешения ПК: " + err));
    return;
  }
  onRefreshBinding();
  addStatus("ПК разрешен");
}

void AdminWindow::onBlockClient() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }

  bool ok = false;
  QString client_id = QInputDialog::getText(this,
                                            "Заблокировать ПК",
                                            "Client ID:",
                                            QLineEdit::Normal,
                                            "",
                                            &ok);
  if (!ok || client_id.isEmpty()) return;

  std::string err;
  if (!client_.set_client_allowed(*device, client_id.toStdString(), false, &err)) {
    addStatus(QString::fromStdString("Ошибка блокировки ПК: " + err));
    return;
  }
  onRefreshBinding();
  addStatus("ПК заблокирован");
}

void AdminWindow::onUnlockUser() {
  auto* device = selectedDevice();
  if (!device) {
    addStatus("Выберите устройство");
    return;
  }

  std::vector<std::string> locks;
  std::string err;
  if (!client_.get_locks(*device, 200, &locks, &err)) {
    addStatus(QString::fromStdString("Ошибка получения блокировок: " + err));
    return;
  }

  QStringList users;
  for (const auto& line : locks) {
    auto p = split_pipe(line);
    if (!p.empty()) users << QString::fromStdString(p[0]);
  }
  users.removeDuplicates();
  if (users.isEmpty()) {
    addStatus("Активных блокировок нет");
    return;
  }

  bool ok = false;
  QString user = QInputDialog::getItem(this,
                                       "Снять блокировку",
                                       "Пользователь:",
                                       users,
                                       0,
                                       false,
                                       &ok);
  if (!ok || user.isEmpty()) return;

  if (!client_.unlock_user(*device, user.toStdString(), &err)) {
    addStatus(QString::fromStdString("Ошибка снятия блокировки: " + err));
    return;
  }

  onRefreshStats();
  addStatus("Блокировка снята");
}

void AdminWindow::renderPatternAnalysis(const std::vector<std::string>& logs,
                                        const std::vector<std::string>& stats,
                                        const std::vector<std::string>& locks,
                                        const cipheator::AdminDevice& device) {
  std::unordered_map<std::string, PatternStat> data;

  for (const auto& line : logs) {
    auto p = split_pipe(line);
    if (p.size() < 4) continue;
    const std::string& type = p[1];
    const std::string& user = p[2];
    const std::string& detail = p[3];

    auto& d = data[user];
    if (type == "encrypt" || type == "decrypt") d.requests++;
    if (type == "auth_failed") d.auth_failed++;

    uint64_t file_size = extract_uint(detail, "file_size=");
    uint64_t enc_size = extract_uint(detail, "enc_size=");
    uint64_t plain_size = extract_uint(detail, "plain_size=");
    d.bytes_in += (file_size > 0 ? file_size : enc_size);
    d.bytes_out += plain_size;
    d.max_single = std::max(d.max_single, file_size);
    d.max_single = std::max(d.max_single, enc_size);
    d.max_single = std::max(d.max_single, plain_size);
  }

  for (const auto& line : stats) {
    auto p = split_pipe(line);
    if (p.size() < 2) continue;
    auto& d = data[p[0]];
    try {
      d.total_logins = static_cast<uint32_t>(std::stoul(p[1]));
    } catch (...) {
      d.total_logins = 0;
    }
  }

  for (const auto& line : locks) {
    auto p = split_pipe(line);
    if (p.size() < 3) continue;
    auto& d = data[p[0]];
    d.locked = true;
    try {
      d.lock_remaining = std::stoll(p[2]);
    } catch (...) {
      d.lock_remaining = 0;
    }
  }

  QString report;
  report += QString("Устройство: %1 (%2:%3)\n\n")
                .arg(QString::fromStdString(device.name))
                .arg(QString::fromStdString(device.host))
                .arg(device.port);

  if (data.empty()) {
    report += "Нет данных для анализа.\n";
    analysis_view_->setPlainText(report);
    return;
  }

  bool has_findings = false;
  for (const auto& kv : data) {
    const auto& user = kv.first;
    const auto& d = kv.second;
    report += "Пользователь: " + QString::fromStdString(user) + "\n";
    report += "  Запросы: " + QString::number(static_cast<qulonglong>(d.requests)) + "\n";
    report += "  Входящие данные: " + bytes_to_mb(d.bytes_in) + "\n";
    report += "  Исходящие данные: " + bytes_to_mb(d.bytes_out) + "\n";
    report += "  Макс. разовый объем: " + bytes_to_mb(d.max_single) + "\n";
    report += "  Ошибки входа: " + QString::number(static_cast<qulonglong>(d.auth_failed)) + "\n";
    report += "  Всего логинов: " + QString::number(d.total_logins) + "\n";

    QStringList flags;
    if (d.requests >= 12) flags << "очень частые запросы";
    if (d.bytes_in >= 200ULL * 1024ULL * 1024ULL || d.bytes_out >= 200ULL * 1024ULL * 1024ULL) {
      flags << "большие объемы данных";
    }
    if (d.max_single >= 50ULL * 1024ULL * 1024ULL) flags << "крупные разовые передачи";
    if (d.auth_failed >= 3) flags << "частые ошибки аутентификации";
    if (d.locked) flags << QString("аккаунт заблокирован (%1 сек)").arg(d.lock_remaining);

    if (!flags.isEmpty()) {
      has_findings = true;
      report += "  Аномалии: " + flags.join(", ") + "\n";
    } else {
      report += "  Аномалии: не обнаружены\n";
    }
    report += "\n";
  }

  report += has_findings
      ? "Итог: есть отклонения от типичного поведения.\n"
      : "Итог: отклонений не обнаружено.\n";

  analysis_view_->setPlainText(report);
}

void AdminWindow::onAutoRefresh() {
  onRefreshAlerts();
  onRefreshBinding();
  onRefreshLogs();
  onRefreshStats();
}

void AdminWindow::addStatus(const QString& text) {
  status_label_->setText(text);
}
