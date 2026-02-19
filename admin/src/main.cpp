#include "admin_window.h"

#include "cipheator/config.h"

#include <QApplication>

int main(int argc, char** argv) {
  QApplication app(argc, argv);

  cipheator::Config config;
  config.load("config/admin.conf");

  cipheator::AdminConfig admin_cfg;
  admin_cfg.ca_file = config.get("ca_file");
  admin_cfg.client_cert = config.get("client_cert");
  admin_cfg.client_key = config.get("client_key");
  admin_cfg.verify_peer = config.get_bool("verify_peer", true);

  AdminWindow window(admin_cfg);
  window.show();

  return app.exec();
}
