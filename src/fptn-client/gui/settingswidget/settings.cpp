/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/settingswidget/settings.h"

#include "gui/sni_autoscan_dialog/sni_autoscan_dialog.h"

#if _WIN32
#include <Ws2tcpip.h>  // NOLINT(build/include_order)
#include <windows.h>   // NOLINT(build/include_order)
#endif

#include <utility>

#include <QApplication>                 // NOLINT(build/include_order)
#include <QFileDialog>                  // NOLINT(build/include_order)
#include <QGridLayout>                  // NOLINT(build/include_order)
#include <QHeaderView>                  // NOLINT(build/include_order)
#include <QLabel>                       // NOLINT(build/include_order)
#include <QLineEdit>                    // NOLINT(build/include_order)
#include <QMessageBox>                  // NOLINT(build/include_order)
#include <QPainter>                     // NOLINT(build/include_order)
#include <QPushButton>                  // NOLINT(build/include_order)
#include <QRegularExpressionValidator>  // NOLINT(build/include_order)
#include <QScrollArea>                  // NOLINT(build/include_order)
#include <QSystemTrayIcon>              // NOLINT(build/include_order)
#include <QTableWidgetItem>             // NOLINT(build/include_order)

#include "gui/autostart/autostart.h"
#include "gui/tokendialog/tokendialog.h"
#include "gui/translations/translations.h"

namespace {
constexpr int kAdvancedIndent = 10;

QString CleanDomain(const QString& domain) {
  if (domain.isEmpty()) {
    return domain;
  }

  QString cleaned;
  cleaned.reserve(domain.length());

  static QRegularExpression valid_chars("[a-zA-Z0-9.-]");

  for (int i = 0; i < domain.length(); ++i) {
    QChar ch = domain[i];

    if (valid_chars.match(ch).hasMatch()) {
      cleaned.append(ch.toLower());
    }
  }
  return cleaned;
}

QString VectorToText(const QVector<QString>& items) { return items.join('\n'); }

QVector<QString> TextToVector(const QString& text) {
  QVector<QString> result;
  const auto lines = text.split('\n', Qt::SkipEmptyParts);
  for (const auto& line : lines) {
    result.append(line.trimmed());
  }
  return result;
}

QTableWidgetItem* CenteredItem(const QString& text) {
  auto* item = new QTableWidgetItem(text);
  item->setTextAlignment(Qt::AlignCenter);
  return item;
}

QIcon ChevronIcon(bool expanded, const QColor& color) {
  QPixmap pixmap(16, 16);
  pixmap.fill(Qt::transparent);

  QPainter painter(&pixmap);
  painter.setRenderHint(QPainter::Antialiasing);
  QPen pen(color);
  pen.setWidthF(1.5);
  pen.setCapStyle(Qt::RoundCap);
  pen.setJoinStyle(Qt::RoundJoin);
  painter.setPen(pen);

  QPolygonF chevron;
  if (expanded) {
    chevron << QPointF(4.5, 6.5) << QPointF(8.0, 10.0) << QPointF(11.5, 6.5);
  } else {
    chevron << QPointF(6.5, 4.5) << QPointF(10.0, 8.0) << QPointF(6.5, 11.5);
  }
  painter.drawPolyline(chevron);

  return QIcon(pixmap);
}
}  // namespace

using fptn::gui::SettingsWidget;

SettingsWidget::SettingsWidget(SettingsModelPtr settings, QWidget* parent)
    : QDialog(parent), settings_(std::move(settings)) {
  SetupUi();
  setWindowIcon(QIcon(":/icons/app.ico"));
  // show on top
  setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
  setModal(true);
  show();
  activateWindow();
  raise();
  setWindowTitle(QObject::tr("Settings"));
}

void SettingsWidget::SetupUi() {
  tab_widget_ = new QTabWidget(this);
  tab_widget_->setContextMenuPolicy(Qt::ActionsContextMenu);

  // ==================== Settings Tab ====================
  settings_tab_ = new QWidget();
  auto* main_settings_layout = new QVBoxLayout(settings_tab_);
  main_settings_layout->setContentsMargins(0, 0, 0, 0);
  auto* settings_scroll_area = new QScrollArea(this);
  settings_scroll_area->setWidgetResizable(true);
  settings_scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
  settings_scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
  settings_scroll_area->setFrameShape(QFrame::NoFrame);

  auto* settings_content_widget = new QWidget();
  settings_content_widget->setMinimumWidth(600);
  auto* settings_layout = new QVBoxLayout(settings_content_widget);
  settings_layout->setContentsMargins(10, 5, 5, 5);

  grid_layout_ = new QGridLayout();
  grid_layout_->setContentsMargins(0, 0, 0, 0);
  grid_layout_->setHorizontalSpacing(10);
  grid_layout_->setVerticalSpacing(5);
  grid_layout_->setColumnStretch(0, 0);
  grid_layout_->setColumnStretch(1, 1);
  grid_layout_->setColumnMinimumWidth(0, 380);

#ifdef __linux__
  autostart_label_ = new QLabel(QObject::tr("Autostart"), this);
  autostart_checkbox_ = new QCheckBox(" ", this);
  autostart_checkbox_->setChecked(settings_->Autostart());
  connect(autostart_checkbox_, &QCheckBox::toggled, this,
      &SettingsWidget::onAutostartChanged);
  grid_layout_->addWidget(autostart_label_, 0, 0, Qt::AlignLeft);
  grid_layout_->addWidget(autostart_checkbox_, 0, 1, Qt::AlignLeft);
#endif

  language_label_ = new QLabel(QObject::tr("Language"), this);
  language_combo_box_ = new QComboBox(this);
  language_combo_box_->addItems(settings_->GetLanguages());
  language_combo_box_->setCurrentText(settings_->LanguageName());
  language_combo_box_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  connect(language_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onLanguageChanged);
  grid_layout_->addWidget(language_label_, 1, 0, Qt::AlignLeft);
  grid_layout_->addWidget(language_combo_box_, 1, 1);

  enable_ad_block_label_ = new QLabel(QObject::tr("Block ads"), this);
  enable_ad_block_checkbox_ = new QCheckBox(" ", this);
  enable_ad_block_checkbox_->setChecked(settings_->EnableAdBlock());
  connect(enable_ad_block_checkbox_, &QCheckBox::toggled, this,
      [this](bool checked) { settings_->SetEnableAdBlock(checked); });
  grid_layout_->addWidget(enable_ad_block_label_, 2, 0, Qt::AlignLeft);
  grid_layout_->addWidget(enable_ad_block_checkbox_, 2, 1, Qt::AlignLeft);

  interface_label_ =
      new QLabel(QObject::tr("Network Interface (adapter)"), this);
  interface_combo_box_ = new QComboBox(this);
  interface_combo_box_->addItems(settings_->GetNetworkInterfaces());
  interface_combo_box_->setCurrentText(settings_->UsingNetworkInterface());
  interface_combo_box_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  connect(interface_combo_box_, &QComboBox::currentTextChanged, this,
      &SettingsWidget::onInterfaceChanged);
  grid_layout_->addWidget(interface_label_, 3, 0, Qt::AlignLeft);
  grid_layout_->addWidget(interface_combo_box_, 3, 1);

  gateway_label_ = new QLabel(
      QObject::tr("Gateway IP Address (typically your router's address)"),
      this);
  gateway_auto_checkbox_ = new QCheckBox(QObject::tr("Auto"), this);
  gateway_line_edit_ = new QLineEdit(this);
  if (settings_->GatewayIp().toLower() != "auto") {
    gateway_auto_checkbox_->setChecked(false);
    gateway_line_edit_->setText(settings_->GatewayIp());
    gateway_line_edit_->setEnabled(true);
    gateway_line_edit_->setPlaceholderText("192.168.1.1");
  } else {
    gateway_auto_checkbox_->setChecked(true);
    gateway_line_edit_->setDisabled(true);
  }
  connect(gateway_auto_checkbox_, &QCheckBox::toggled, this,
      &SettingsWidget::onAutoGatewayChanged);

  auto* gateway_layout = new QHBoxLayout();
  gateway_layout->addWidget(gateway_auto_checkbox_);
  gateway_layout->addWidget(gateway_line_edit_);
  gateway_layout->setStretch(0, 0);
  gateway_layout->setStretch(1, 1);

  grid_layout_->addWidget(gateway_label_, 4, 0, Qt::AlignLeft);
  grid_layout_->addLayout(gateway_layout, 4, 1);

  custom_dns_label_ = new QLabel(QObject::tr("Custom DNS"), this);
  custom_dns_auto_checkbox_ = new QCheckBox(QObject::tr("Auto"), this);
  custom_dns_line_edit_ = new QLineEdit(this);
  const QString ipv4_octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  custom_dns_line_edit_->setValidator(new QRegularExpressionValidator(
      QRegularExpression("^(" + ipv4_octet + "\\.){3}" + ipv4_octet + "$"),
      this));
  if (!settings_->CustomDns().isEmpty()) {
    custom_dns_auto_checkbox_->setChecked(false);
    custom_dns_line_edit_->setText(settings_->CustomDns());
    custom_dns_line_edit_->setEnabled(true);
    custom_dns_line_edit_->setPlaceholderText("8.8.8.8");
  } else {
    custom_dns_auto_checkbox_->setChecked(true);
    custom_dns_line_edit_->setDisabled(true);
  }
  connect(custom_dns_auto_checkbox_, &QCheckBox::toggled, this,
      &SettingsWidget::onAutoCustomDnsChanged);

  auto* custom_dns_layout = new QHBoxLayout();
  custom_dns_layout->addWidget(custom_dns_auto_checkbox_);
  custom_dns_layout->addWidget(custom_dns_line_edit_);
  custom_dns_layout->setStretch(0, 0);
  custom_dns_layout->setStretch(1, 1);

  grid_layout_->addWidget(custom_dns_label_, 5, 0, Qt::AlignLeft);
  grid_layout_->addLayout(custom_dns_layout, 5, 1);

  connection_strategy_label_ =
      new QLabel(QObject::tr("Connection strategy"), this);
  connection_strategy_combo_box_ = new QComboBox(this);
  connection_strategy_combo_box_->addItem(
      QObject::tr("Rolling tunnel"), SettingsModel::kConnectionStrategyRolling);
  connection_strategy_combo_box_->addItem(QObject::tr("Dual rolling tunnel"),
      SettingsModel::kConnectionStrategyDual);
  connection_strategy_combo_box_->addItem(QObject::tr("Triple rolling tunnel"),
      SettingsModel::kConnectionStrategyTriple);
  connection_strategy_combo_box_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  connection_strategy_combo_box_->setMinimumWidth(200);

  const int connection_strategy_index =
      connection_strategy_combo_box_->findData(settings_->ConnectionStrategy());
  connection_strategy_combo_box_->setCurrentIndex(
      connection_strategy_index >= 0 ? connection_strategy_index : 0);

  connect(connection_strategy_combo_box_, &QComboBox::currentIndexChanged, this,
      [this](int) {
        settings_->SetConnectionStrategy(
            connection_strategy_combo_box_->currentData().toString());
      });

  grid_layout_->addWidget(connection_strategy_label_, 6, 0, Qt::AlignLeft);
  grid_layout_->addWidget(connection_strategy_combo_box_, 6, 1);

  bypass_method_label_ =
      new QLabel(QObject::tr("Bypass blocking method"), this);
  bypass_method_combo_box_ = new QComboBox(this);
  FillBypassMethodComboBox();

  bypass_method_combo_box_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  bypass_method_combo_box_->setMinimumWidth(200);

  connect(bypass_method_combo_box_, &QComboBox::currentIndexChanged, this,
      [this](int) {
        onBypassMethodChanged(
            bypass_method_combo_box_->currentData().toString());
      });

  grid_layout_->addWidget(bypass_method_label_, 7, 0, Qt::AlignLeft);
  grid_layout_->addWidget(bypass_method_combo_box_, 7, 1);

  sni_label_ = new QLabel(this);
  if (settings_->BypassMethod() != SettingsModel::kBypassMethodSni) {
    sni_label_->setText(QObject::tr("Fake domain to bypass blocking"));
  }
  sni_label_->setMinimumHeight(30);
  sni_label_->setWordWrap(true);
  sni_line_edit_ = new QLineEdit(this);
  sni_line_edit_->setText(settings_->SNI());
  sni_line_edit_->setMinimumWidth(200);
  sni_label_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
  sni_line_edit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  connect(sni_line_edit_, &QLineEdit::textChanged, this,
      [this](const QString& text) {
        if (text.isEmpty()) {
          settings_->SetSNI(FPTN_DEFAULT_SNI);
          return;
        }
        QString normalized = CleanDomain(text.toLower());
        if (normalized != text) {
          sni_line_edit_->blockSignals(true);
          sni_line_edit_->setText(normalized);
          sni_line_edit_->blockSignals(false);
        }
        settings_->SetSNI(normalized);
      });

  grid_layout_->addWidget(sni_label_, 8, 0, Qt::AlignLeft | Qt::AlignVCenter);
  grid_layout_->addWidget(sni_line_edit_, 8, 1);

  sni_files_list_widget_ = new QListWidget(this);
  sni_files_list_widget_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
  sni_files_list_widget_->setMaximumHeight(60);

  sni_buttons_layout_ = new QHBoxLayout();

  sni_autoscan_button_ = new QPushButton(QObject::tr("Autoscan SNI"), this);
  sni_import_button_ = new QPushButton(QObject::tr("Import SNI file"), this);

  sni_buttons_layout_->addWidget(sni_autoscan_button_);
  sni_buttons_layout_->addSpacing(10);
  sni_buttons_layout_->addWidget(sni_import_button_);
  sni_buttons_layout_->addStretch(1);

  sni_autoscan_button_->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
  sni_import_button_->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

  grid_layout_->addLayout(sni_buttons_layout_, 9, 0, 1, 2);
  grid_layout_->addWidget(sni_files_list_widget_, 10, 0, 1, 2);
  connect(sni_autoscan_button_, &QPushButton::clicked, this,
      &SettingsWidget::onAutoscanClicked);

  connect(sni_import_button_, &QPushButton::clicked, this,
      &SettingsWidget::onImportSniFile);

  settings_layout->addLayout(grid_layout_, 1);

  server_table_ = new QTableWidget(0, 4, this);
  server_table_->setHorizontalHeaderLabels(
      {QObject::tr("Service name"), QObject::tr("Token updated"),
          QObject::tr("User"), QObject::tr("Action")});
  server_table_->horizontalHeader()->setStretchLastSection(false);
  server_table_->horizontalHeader()->setSectionResizeMode(
      0, QHeaderView::Stretch);
  server_table_->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::Stretch);
  server_table_->horizontalHeader()->setSectionResizeMode(
      2, QHeaderView::Stretch);
  server_table_->horizontalHeader()->setSectionResizeMode(
      3, QHeaderView::ResizeToContents);

  server_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  server_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  server_table_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  server_table_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
  server_table_->verticalHeader()->setVisible(false);
  server_table_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
  server_table_->verticalHeader()->setDefaultSectionSize(36);
  server_table_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
  server_table_->setMinimumHeight(120);

  grid_layout_->addWidget(server_table_, 11, 0, 1, 2);
  grid_layout_->setRowStretch(11, 1);

  settings_scroll_area->setWidget(settings_content_widget);
  main_settings_layout->addWidget(settings_scroll_area);

  tab_widget_->addTab(settings_tab_, QObject::tr("Settings"));

  // ==================== Routing Tab ====================
  routing_tab_ = new QWidget();
  auto* main_routing_layout = new QVBoxLayout(routing_tab_);
  main_routing_layout->setContentsMargins(0, 0, 0, 0);

  auto* routing_scroll_area = new QScrollArea(this);
  routing_scroll_area->setWidgetResizable(true);
  routing_scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  routing_scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
  routing_scroll_area->setFrameShape(QFrame::NoFrame);

  auto* routing_content_widget = new QWidget();
  auto* routing_layout = new QVBoxLayout(routing_content_widget);
  routing_layout->setContentsMargins(10, 10, 5, 10);
  routing_layout->setSpacing(5);

  routing_grid_layout_ = new QGridLayout();
  routing_grid_layout_->setContentsMargins(0, 0, 0, 0);
  routing_grid_layout_->setHorizontalSpacing(10);
  routing_grid_layout_->setVerticalSpacing(5);
  routing_grid_layout_->setColumnStretch(0, 1);
  routing_grid_layout_->setColumnStretch(1, 2);

  int current_row = 0;

#ifdef _WIN32
  constexpr char kInfoLabelStyle[] = "color: #111111; font-size: 7pt;";
#elif defined(__APPLE__)
  constexpr char kInfoLabelStyle[] = "color: #888888; font-size: 9pt;";
#elif defined(__linux__)
  constexpr char kInfoLabelStyle[] = "color: #111111; font-size: 8pt;";
#endif

// Routing
#if _WIN32
  // DNS Management
  enable_dns_management_label_ =
      new QLabel(QObject::tr("Enable advanced DNS management"), this);
  enable_dns_management_info_label_ = new QLabel(
      QObject::tr("Enables advanced DNS configuration to prevent leaks. "
                  "Recommended when using split tunneling. Use with caution!"),
      this);
  enable_dns_management_info_label_->setWordWrap(true);
  enable_dns_management_info_label_->setAlignment(
      Qt::AlignLeft | Qt::AlignTop);
  enable_dns_management_info_label_->setStyleSheet(kInfoLabelStyle);
  enable_dns_management_info_label_->setMinimumHeight(70);
  auto* dns_label_container = new QWidget(this);
  auto* dns_label_layout = new QVBoxLayout(dns_label_container);
  dns_label_layout->setContentsMargins(0, 0, 0, 0);
  dns_label_layout->addWidget(
      enable_dns_management_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  dns_label_layout->addWidget(
      enable_dns_management_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  dns_label_layout->addStretch(1);

  enable_dns_management_checkbox_ = new QCheckBox(" ", this);
  enable_dns_management_checkbox_->setChecked(
      settings_->EnableAdvancedDnsManagement());
  connect(enable_dns_management_checkbox_, &QCheckBox::toggled, this,
      [this](bool checked) {
        settings_->SetEnableAdvancedDnsManagement(checked);
      });

  dns_label_container->setVisible(false);
  enable_dns_management_checkbox_->setVisible(false);
#endif

  enable_split_tunnel_label_ =
      new QLabel(QObject::tr("Enable split tunnel"), this);
  enable_split_tunnel_info_label_ =
      new QLabel(QObject::tr("When enabled, you can configure which sites use "
                             "VPN and which go directly."),
          this);
  enable_split_tunnel_info_label_->setWordWrap(true);
  enable_split_tunnel_info_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
  enable_split_tunnel_info_label_->setMinimumHeight(60);
  enable_split_tunnel_info_label_->setStyleSheet(kInfoLabelStyle);

  auto* enable_split_label_container = new QWidget(this);
  auto* enable_split_label_layout =
      new QVBoxLayout(enable_split_label_container);
  enable_split_label_layout->setContentsMargins(0, 0, 0, 0);
  enable_split_label_layout->addWidget(
      enable_split_tunnel_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  enable_split_label_layout->addWidget(
      enable_split_tunnel_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  enable_split_label_layout->addStretch(1);

  enable_split_tunnel_checkbox_ = new QCheckBox(" ", this);
  enable_split_tunnel_checkbox_->setChecked(settings_->EnableSplitTunnel());
  connect(enable_split_tunnel_checkbox_, &QCheckBox::toggled, this,
      [this](bool checked) {
        split_tunnel_mode_label_->setVisible(checked);
        split_tunnel_mode_info_label_->setVisible(checked);
        split_tunnel_mode_combo_box_->setVisible(checked);
        split_tunnel_domains_label_->setVisible(checked);
        split_tunnel_domains_info_label_->setVisible(checked);
        split_tunnel_domains_text_edit_->setVisible(checked);
        settings_->SetEnableSplitTunnel(checked);
      });

  routing_grid_layout_->addWidget(enable_split_label_container, current_row, 0,
      Qt::AlignLeft | Qt::AlignTop);
  routing_grid_layout_->addWidget(enable_split_tunnel_checkbox_, current_row, 1,
      Qt::AlignLeft | Qt::AlignTop);
  current_row++;

  split_tunnel_mode_label_ = new QLabel(QObject::tr("Split tunnel mode"), this);
  split_tunnel_mode_info_label_ = new QLabel(
      QObject::tr("Defines traffic routing strategy for split tunneling."),
      this);
  split_tunnel_mode_info_label_->setWordWrap(true);
  split_tunnel_mode_info_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
  split_tunnel_mode_info_label_->setMinimumHeight(60);
  split_tunnel_mode_info_label_->setStyleSheet(kInfoLabelStyle);

  auto* split_mode_label_container = new QWidget(this);
  auto* split_mode_label_layout = new QVBoxLayout(split_mode_label_container);
  split_mode_label_layout->setContentsMargins(0, 0, 0, 0);
  split_mode_label_layout->addWidget(
      split_tunnel_mode_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  split_mode_label_layout->addWidget(
      split_tunnel_mode_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  split_mode_label_layout->addStretch(1);

  split_tunnel_mode_combo_box_ = new QComboBox(this);
  split_tunnel_mode_combo_box_->setMinimumWidth(200);
  split_tunnel_mode_combo_box_->addItem(
      QObject::tr("Exclude"), SettingsModel::kSplitTunnelModeExclude);
  split_tunnel_mode_combo_box_->addItem(
      QObject::tr("Include"), SettingsModel::kSplitTunnelModeInclude);
  split_tunnel_mode_combo_box_->setCurrentText(
      settings_->SplitTunnelMode() == SettingsModel::kSplitTunnelModeInclude
          ? QObject::tr("Include")
          : QObject::tr("Exclude"));

  connect(split_tunnel_mode_combo_box_, &QComboBox::currentTextChanged, this,
      [this](const QString& mode) {
        if (mode == QObject::tr("Include") ||
            mode == SettingsModel::kSplitTunnelModeInclude) {
          settings_->SetSplitTunnelMode(SettingsModel::kSplitTunnelModeInclude);
          split_tunnel_domains_label_->setText(
              QObject::tr("Domains to route through VPN"));
          split_tunnel_domains_info_label_->setText(
              QObject::tr("List domains that should use VPN tunnel. "
                          "Only these domains will go through VPN, "
                          "all other traffic bypasses VPN"));
        } else {
          settings_->SetSplitTunnelMode(SettingsModel::kSplitTunnelModeExclude);
          split_tunnel_domains_label_->setText(
              QObject::tr("Domains to bypass VPN"));

          split_tunnel_domains_info_label_->setText(
              QObject::tr("List domains that should bypass VPN tunnel. "
                          "These domains will go directly, "
                          "all other traffic uses VPN"));
        }
      });

  routing_grid_layout_->addWidget(
      split_mode_label_container, current_row, 0, Qt::AlignLeft | Qt::AlignTop);
  routing_grid_layout_->addWidget(split_tunnel_mode_combo_box_, current_row, 1,
      Qt::AlignLeft | Qt::AlignTop);
  current_row++;

  split_tunnel_domains_label_ = new QLabel(this);
  if (settings_->SplitTunnelMode() == SettingsModel::kSplitTunnelModeInclude) {
    split_tunnel_domains_label_->setText(
        QObject::tr("Domains to route through VPN"));
  } else {
    split_tunnel_domains_label_->setText(QObject::tr("Domains to bypass VPN"));
  }

  split_tunnel_domains_info_label_ = new QLabel(this);
  if (settings_->SplitTunnelMode() == SettingsModel::kSplitTunnelModeInclude) {
    split_tunnel_domains_info_label_->setText(QObject::tr(
        "List domains that should use VPN tunnel. Only these domains will go "
        "through VPN, all other traffic bypasses VPN"));
  } else {
    split_tunnel_domains_info_label_->setText(
        QObject::tr("List domains that should bypass VPN tunnel. These domains "
                    "will go directly, all other traffic uses VPN"));
  }
  split_tunnel_domains_info_label_->setWordWrap(true);
  split_tunnel_domains_info_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
  split_tunnel_domains_info_label_->setStyleSheet(kInfoLabelStyle);

  auto* split_domains_label_container = new QWidget(this);
  auto* split_domains_label_layout =
      new QVBoxLayout(split_domains_label_container);
  split_domains_label_layout->setContentsMargins(0, 0, 0, 0);
  split_domains_label_layout->addWidget(
      split_tunnel_domains_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  split_domains_label_layout->addWidget(
      split_tunnel_domains_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);

  split_tunnel_domains_text_edit_ = new QTextEdit(this);
  split_tunnel_domains_text_edit_->setPlainText(
      VectorToText(settings_->SplitTunnelDomains()));
  split_tunnel_domains_text_edit_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Expanding);
  split_tunnel_domains_text_edit_->setMinimumHeight(80);
  split_tunnel_domains_text_edit_->setPlaceholderText(
      QObject::tr("com\nanother.com\nsub.domainname.com"));
  connect(
      split_tunnel_domains_text_edit_, &QTextEdit::textChanged, this, [this]() {
        settings_->SetSplitTunnelDomains(
            TextToVector(split_tunnel_domains_text_edit_->toPlainText()));
      });

  routing_grid_layout_->addWidget(split_domains_label_container, current_row, 0,
      Qt::AlignLeft | Qt::AlignTop);
  routing_grid_layout_->addWidget(
      split_tunnel_domains_text_edit_, current_row, 1);
  routing_grid_layout_->setRowStretch(current_row, 1);
  current_row++;

  bool split_enabled = settings_->EnableSplitTunnel();
  split_tunnel_mode_label_->setVisible(split_enabled);
  split_tunnel_mode_info_label_->setVisible(split_enabled);
  split_tunnel_mode_combo_box_->setVisible(split_enabled);
  split_tunnel_domains_label_->setVisible(split_enabled);
  split_tunnel_domains_info_label_->setVisible(split_enabled);
  split_tunnel_domains_text_edit_->setVisible(split_enabled);

  const QColor chevron_color = palette().color(QPalette::WindowText);

  advanced_routing_button_ = new QToolButton(this);
  advanced_routing_button_->setText(QObject::tr("Advanced"));
  advanced_routing_button_->setFont(QApplication::font("QLabel"));
  advanced_routing_button_->setIcon(ChevronIcon(false, chevron_color));
  advanced_routing_button_->setIconSize(QSize(16, 16));
  advanced_routing_button_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
  advanced_routing_button_->setLayoutDirection(Qt::RightToLeft);
  advanced_routing_button_->setCheckable(true);
  advanced_routing_button_->setCursor(Qt::PointingHandCursor);
  advanced_routing_button_->setStyleSheet(R"(
      QToolButton {
          border: none;
          background: transparent;
          padding: 4px 0px;
      }
      QToolButton:checked {
          border: none;
          background: transparent;
      }
  )");
  connect(advanced_routing_button_, &QToolButton::toggled, this,
      [this, chevron_color](bool checked) {
        advanced_routing_button_->setIcon(ChevronIcon(checked, chevron_color));
        for (auto* widget : advanced_routing_widgets_) {
          widget->setVisible(checked);
        }
      });
  routing_grid_layout_->addWidget(advanced_routing_button_, current_row, 0, 1,
      2, Qt::AlignLeft | Qt::AlignAbsolute);
  current_row++;

  blacklist_domains_label_ = new QLabel(QObject::tr("Blacklist domains"), this);
  blacklist_domains_info_label_ = new QLabel(
      QObject::tr("Completely block access to the main domain AND all its "
                  "subdomains. Format: example.com (one per line)"),
      this);
  blacklist_domains_info_label_->setWordWrap(true);
  blacklist_domains_info_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
  blacklist_domains_info_label_->setMinimumHeight(60);
  blacklist_domains_info_label_->setStyleSheet(kInfoLabelStyle);

  auto* blacklist_label_container = new QWidget(this);
  auto* blacklist_label_layout = new QVBoxLayout(blacklist_label_container);
  blacklist_label_layout->setContentsMargins(kAdvancedIndent, 0, 0, 0);
  blacklist_label_layout->addWidget(
      blacklist_domains_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  blacklist_label_layout->addWidget(
      blacklist_domains_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);

  blacklist_domains_text_edit_ = new QTextEdit(this);
  blacklist_domains_text_edit_->setPlainText(
      VectorToText(settings_->BlacklistDomains()));
  blacklist_domains_text_edit_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  blacklist_domains_text_edit_->setMaximumHeight(60);
  connect(
      blacklist_domains_text_edit_, &QTextEdit::textChanged, this, [this]() {
        settings_->SetBlacklistDomains(
            TextToVector(blacklist_domains_text_edit_->toPlainText()));
      });

  routing_grid_layout_->addWidget(
      blacklist_label_container, current_row, 0, Qt::AlignLeft | Qt::AlignTop);
  routing_grid_layout_->addWidget(blacklist_domains_text_edit_, current_row, 1);
  current_row++;
  advanced_routing_widgets_.push_back(blacklist_label_container);
  advanced_routing_widgets_.push_back(blacklist_domains_text_edit_);

  exclude_tunnel_networks_label_ =
      new QLabel(QObject::tr("Exclude tunnel networks"), this);
  exclude_tunnel_networks_info_label_ = new QLabel(
      QObject::tr("Networks that always bypass VPN tunnel. "
                  "Traffic to these networks goes directly, never through VPN"),
      this);
  exclude_tunnel_networks_info_label_->setWordWrap(true);
  exclude_tunnel_networks_info_label_->setAlignment(
      Qt::AlignLeft | Qt::AlignTop);
  exclude_tunnel_networks_info_label_->setMinimumHeight(60);
  exclude_tunnel_networks_info_label_->setStyleSheet(kInfoLabelStyle);

  auto* exclude_label_container = new QWidget(this);
  auto* exclude_label_layout = new QVBoxLayout(exclude_label_container);
  exclude_label_layout->setContentsMargins(kAdvancedIndent, 0, 0, 0);
  exclude_label_layout->addWidget(
      exclude_tunnel_networks_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  exclude_label_layout->addWidget(
      exclude_tunnel_networks_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);

  exclude_tunnel_networks_text_edit_ = new QTextEdit(this);
  exclude_tunnel_networks_text_edit_->setPlainText(
      VectorToText(settings_->ExcludeTunnelNetworks()));
  exclude_tunnel_networks_text_edit_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  exclude_tunnel_networks_text_edit_->setMaximumHeight(60);
  connect(exclude_tunnel_networks_text_edit_, &QTextEdit::textChanged, this,
      [this]() {
        settings_->SetExcludeTunnelNetworks(
            TextToVector(exclude_tunnel_networks_text_edit_->toPlainText()));
      });

  routing_grid_layout_->addWidget(
      exclude_label_container, current_row, 0, Qt::AlignLeft | Qt::AlignTop);
  routing_grid_layout_->addWidget(
      exclude_tunnel_networks_text_edit_, current_row, 1);
  current_row++;
  advanced_routing_widgets_.push_back(exclude_label_container);
  advanced_routing_widgets_.push_back(exclude_tunnel_networks_text_edit_);

  include_tunnel_networks_label_ =
      new QLabel(QObject::tr("Include tunnel networks"), this);
  include_tunnel_networks_info_label_ = new QLabel(
      QObject::tr("Networks that always use VPN tunnel. "
                  "Traffic to these networks always goes through VPN"),
      this);
  include_tunnel_networks_info_label_->setWordWrap(true);
  include_tunnel_networks_info_label_->setAlignment(
      Qt::AlignLeft | Qt::AlignTop);
  include_tunnel_networks_info_label_->setMinimumHeight(60);
  include_tunnel_networks_info_label_->setStyleSheet(kInfoLabelStyle);

  auto* include_label_container = new QWidget(this);
  auto* include_label_layout = new QVBoxLayout(include_label_container);
  include_label_layout->setContentsMargins(kAdvancedIndent, 0, 0, 0);
  include_label_layout->addWidget(
      include_tunnel_networks_label_, 0, Qt::AlignLeft | Qt::AlignTop);
  include_label_layout->addWidget(
      include_tunnel_networks_info_label_, 0, Qt::AlignLeft | Qt::AlignTop);

  include_tunnel_networks_text_edit_ = new QTextEdit(this);
  include_tunnel_networks_text_edit_->setPlainText(
      VectorToText(settings_->IncludeTunnelNetworks()));
  include_tunnel_networks_text_edit_->setSizePolicy(
      QSizePolicy::Expanding, QSizePolicy::Fixed);
  include_tunnel_networks_text_edit_->setMaximumHeight(60);
  include_tunnel_networks_text_edit_->setPlaceholderText(
      QObject::tr("192.168.99.0/24"));
  connect(include_tunnel_networks_text_edit_, &QTextEdit::textChanged, this,
      [this]() {
        settings_->SetIncludeTunnelNetworks(
            TextToVector(include_tunnel_networks_text_edit_->toPlainText()));
      });

  routing_grid_layout_->addWidget(
      include_label_container, current_row, 0, Qt::AlignLeft | Qt::AlignTop);
  routing_grid_layout_->addWidget(
      include_tunnel_networks_text_edit_, current_row, 1);
  advanced_routing_widgets_.push_back(include_label_container);
  advanced_routing_widgets_.push_back(include_tunnel_networks_text_edit_);

  for (auto* widget : advanced_routing_widgets_) {
    widget->setVisible(false);
  }

  routing_layout->addLayout(routing_grid_layout_);

  routing_layout->addStretch(1);

  routing_scroll_area->setWidget(routing_content_widget);
  main_routing_layout->addWidget(routing_scroll_area);

  tab_widget_->addTab(routing_tab_, QObject::tr("Routing"));

  // ==================== About Tab ====================
  about_tab_ = new QWidget();
  auto* main_about_layout = new QVBoxLayout(about_tab_);
  main_about_layout->setContentsMargins(0, 0, 0, 0);

  auto* about_scroll_area = new QScrollArea(this);
  about_scroll_area->setWidgetResizable(true);
  about_scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  about_scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
  about_scroll_area->setFrameShape(QFrame::NoFrame);

  auto* about_content_widget = new QWidget();
  auto* about_layout = new QVBoxLayout(about_content_widget);
  about_layout->setContentsMargins(10, 5, 5, 5);
  about_layout->setSpacing(10);

  auto* fptn_label = new QLabel("FPTN", this);
  fptn_label->setAlignment(Qt::AlignCenter);
  about_layout->addWidget(fptn_label);

  version_label_ = new QLabel(
      QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION), this);
  version_label_->setAlignment(Qt::AlignCenter);
  about_layout->addWidget(version_label_);

  project_info_label_ = new QLabel(QObject::tr("FPTN_DESCRIPTION"), this);
  project_info_label_->setWordWrap(true);
  project_info_label_->setAlignment(Qt::AlignJustify);
  about_layout->addWidget(project_info_label_);

  website_link_label_ =
      new QLabel(QObject::tr("FPTN_WEBSITE_DESCRIPTION"), this);
  website_link_label_->setOpenExternalLinks(true);
  about_layout->addWidget(website_link_label_);

  telegram_group_label_ =
      new QLabel(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"), this);
  telegram_group_label_->setTextFormat(Qt::RichText);
  telegram_group_label_->setTextInteractionFlags(Qt::TextBrowserInteraction);
  telegram_group_label_->setOpenExternalLinks(true);
  about_layout->addWidget(telegram_group_label_);

  boosty_link_label_ =
      new QLabel(QObject::tr("Support the project on") +
                     " <a href=\"https://boosty.to/fptn\">Boosty</a>",
          this);
  boosty_link_label_->setOpenExternalLinks(true);
  boosty_link_label_->setAlignment(Qt::AlignLeft);
  about_layout->addWidget(boosty_link_label_);

  sponsors_label_ = new QLabel(QObject::tr("Project Sponsors"), this);
  sponsors_label_->setAlignment(Qt::AlignLeft);
  about_layout->addWidget(sponsors_label_);

  const QString sponsors_list =
      "  - Brebor<br>"
      "  - miklefox<br>"
      "  - usrbb<br>"
      "  - Secret_Agent_001<br>"
      "  - ragdollmaster<br>"
      "  - slimefrozik<br>"
      "  - HooLigaN<br>"
      "  - Dima<br>"
      "  - Kori<br>"
      "  - DrowASD<br>"
      "  - GΣG 5952<br>"
      "  - NikVas<br>"
      "  - Сергей<br>"
      "  - Frizgy<br>"
      "  - Tired Smi1e<br>"
      "  - Teya Aster<br>"
      "  - loftynite<br>"
      "  - vlz78<br>"
      "  - Erranted<br>"
      "  - Kotishqua<br>"
      "  - Neiros<br>"
      "  - Кабан из AYAYANII<br>"
      "  - Stasyan<br>"
      "  - Daptepik<br>"
      "  - Cu6ic<br>"
      "  - FC<br>"
      "  - Temikin<br>"
      "  - Azeasy<br>"
      "  - NekoDark<br>"
      "  - Alin Zoberg<br>"
      "  - zsergey<br>"
      "  - OlegPaRe<br>"
      "  - Norelax<br>"
      "  - Alligator<br>"
      "  - vblll<br>"
      "  - Ayuemin<br>"
      "  - Semchuk<br>"
      "  - Barzas153<br>"
      "  - machinefactor<br>"
      "  - mahovmm<br>"
      "  - KOTleta<br>"
      "  - Arelost<br>"
      "  - Хмурый<br>"
      "  - 弐式炎雷<br>"
      "  - ☸️Bhagos☸️<br>"
      "  - Pavel<br>"
      "  - zoomzoom<br>"
      "  - Kovalskij<br>"
      "  - Yumarictx<br>"
      "  - ББ<br>"
      "  - huko<br>"
      "  - @UNBREAKABLE189<br>"
      "  - TheChosenOne<br>"
      "  - Noragami9779<br>"
      "  - NightFox<br>"
      "  - puffffik<br>"
      "  - draserg1<br>"
      "  - Artem Kushner<br>"
      "  - AgNeSYUT<br>"
      "  - Blink<br>"
      "  - charlie b.<br>"
      "  - alex_pol<br>"
      "  - Vox<br>"
      "  - Rucozhop4ik<br>"
      "  - Nigmast<br>"
      "  - DayZ_LIDER<br>";

  sponsors_names_label_ = new QLabel(sponsors_list, this);
  sponsors_names_label_->setAlignment(Qt::AlignLeft);
  sponsors_names_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
  sponsors_names_label_->setWordWrap(true);
  about_layout->addWidget(sponsors_names_label_);

  about_layout->addStretch(1);

  about_scroll_area->setWidget(about_content_widget);
  main_about_layout->addWidget(about_scroll_area);

  tab_widget_->addTab(about_tab_, QObject::tr("About"));

  // Setup tabs
  auto* main_layout = new QVBoxLayout(this);
  main_layout->setContentsMargins(5, 5, 5, 5);
  main_layout->addWidget(tab_widget_);

  auto* button_layout = new QHBoxLayout();
  button_layout->addStretch();

  load_new_token_button_ =
      new QPushButton("  " + QObject::tr("Add token") + "  ", this);
  connect(load_new_token_button_, &QPushButton::clicked, this,
      &SettingsWidget::onLoadNewConfig);
  button_layout->addWidget(load_new_token_button_);

  exit_button_ = new QPushButton("  " + QObject::tr("Close") + "  ", this);
  connect(exit_button_, &QPushButton::clicked, this, &SettingsWidget::onExit);
  button_layout->addWidget(exit_button_);

  main_layout->addLayout(button_layout);

  setLayout(main_layout);

  const QVector<ServiceConfig>& services = settings_->Services();
  if (server_table_) {
    server_table_->setRowCount(services.size());
    for (int i = 0; i < services.size(); ++i) {
      const ServiceConfig& service = services[i];
      server_table_->setItem(i, 0, CenteredItem(service.service_name));
      server_table_->setItem(i, 1, CenteredItem(service.token_updated_at));
      server_table_->setItem(i, 2, CenteredItem(service.username));

      auto* delete_button = new QPushButton(QObject::tr("X"), this);
      delete_button->setFixedSize(20, 20);
      delete_button->setStyleSheet(R"(
        QPushButton {
            background-color: transparent;
            border: none;
            font-weight: bold;
            padding: 0px;
        }
        QPushButton:hover {
            color: #cc0000;
        }
        QPushButton:pressed {
            color: #990000;
        }
    )");
      delete_button->setToolTip(QObject::tr("Delete"));
      connect(delete_button, &QPushButton::clicked,
          [this, i]() { onRemoveServer(i); });

      auto* button_container = new QWidget(this);
      auto* action_layout = new QHBoxLayout(button_container);
      action_layout->setContentsMargins(8, 0, 8, 0);
      action_layout->setAlignment(Qt::AlignCenter);
      action_layout->addWidget(delete_button);
      server_table_->setCellWidget(i, 3, button_container);
    }
  }

  onBypassMethodChanged(bypass_method_combo_box_->currentData().toString());

  UpdateSniFilesList();

  resize(680, 500);
  if (tab_widget_) {
    tab_widget_->setCurrentIndex(0);
  }
  UpdateServerTableVisibility();
}

void SettingsWidget::FillBypassMethodComboBox() {
  const QString current_method = settings_->BypassMethod();

  bypass_method_combo_box_->blockSignals(true);
  bypass_method_combo_box_->clear();
  bypass_method_combo_box_->addItem(
      QObject::tr("OBFUSCATION"), SettingsModel::kBypassMethodObfuscation);
  /* Chrome */
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Chrome 149)"),
      SettingsModel::kBypassMethodSniRealityChrome149);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Chrome 148)"),
      SettingsModel::kBypassMethodSniRealityChrome148);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Chrome 147)"),
      SettingsModel::kBypassMethodSniRealityChrome147);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Chrome 146)"),
      SettingsModel::kBypassMethodSniRealityChrome146);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Chrome 145)"),
      SettingsModel::kBypassMethodSniRealityChrome145);
  /* Firefox */
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Firefox 151)"),
      SettingsModel::kBypassMethodSniRealityFirefox151);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Firefox 150)"),
      SettingsModel::kBypassMethodSniRealityFirefox150);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Firefox 149)"),
      SettingsModel::kBypassMethodSniRealityFirefox149);
  /* Yandex */
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Yandex 26.4)"),
      SettingsModel::kBypassMethodSniRealityYandex26_4);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Yandex 26.3)"),
      SettingsModel::kBypassMethodSniRealityYandex26_3);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Yandex 25)"),
      SettingsModel::kBypassMethodSniRealityYandex25);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Yandex 24)"),
      SettingsModel::kBypassMethodSniRealityYandex24);
  /* Safari */
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Safari 26.5)"),
      SettingsModel::kBypassMethodSniRealitySafari26_5);
  bypass_method_combo_box_->addItem(QObject::tr("SNI-REALITY (Safari 26.4)"),
      SettingsModel::kBypassMethodSniRealitySafari26_4);

  const int index = bypass_method_combo_box_->findData(current_method);
  bypass_method_combo_box_->setCurrentIndex(index >= 0 ? index : 0);
  bypass_method_combo_box_->blockSignals(false);
}

void SettingsWidget::onExit() {
  settings_->SetUsingNetworkInterface(interface_combo_box_->currentText());
  settings_->SetLanguage(language_combo_box_->currentText());
  settings_->SetGatewayIp(gateway_line_edit_->text());
  settings_->SetSNI(sni_line_edit_->text());

  if (custom_dns_auto_checkbox_->isChecked()) {
    settings_->SetCustomDns("");
  } else {
    settings_->SetCustomDns(custom_dns_line_edit_->text());
    if (settings_->CustomDns().isEmpty()) {
      custom_dns_auto_checkbox_->setChecked(true);
      QMessageBox::warning(this, QObject::tr("Custom DNS"),
          QObject::tr(
              "Please enter a valid DNS IPv4 address or enable Auto."));
    }
  }

  settings_->SetBypassMethod(
      bypass_method_combo_box_->currentData().toString());

  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }
  this->close();
}

void SettingsWidget::onLoadNewConfig() {
  TokenDialog dialog(this);
  dialog.exec();
  const QString token = dialog.Token();

  // show on top
  show();
  activateWindow();
  raise();

  if (!token.isEmpty()) {
    try {
      ServiceConfig config = settings_->ParseToken(token);
      int exists_index = settings_->GetExistServiceIndex(config.service_name);
      if (exists_index != -1 && server_table_ != nullptr) {
        // remove previous settings
        settings_->RemoveServer(exists_index);
        server_table_->removeRow(exists_index);
      }
      settings_->AddService(config);
      const bool saving_status = settings_->Save();
      if (saving_status && server_table_ != nullptr) {
        // Insert a new row into the server table
        const int new_row = server_table_->rowCount();
        server_table_->insertRow(new_row);

        server_table_->setItem(new_row, 0, CenteredItem(config.service_name));
        server_table_->setItem(
            new_row, 1, CenteredItem(config.token_updated_at));
        server_table_->setItem(new_row, 2, CenteredItem(config.username));

        auto* delete_button = new QPushButton(QObject::tr("X"), this);
        delete_button->setFixedSize(20, 20);
        delete_button->setStyleSheet(R"(
            QPushButton {
                background-color: transparent;
                border: none;
                font-weight: bold;
                padding: 0px;
            }
            QPushButton:hover {
                color: #cc0000;
            }
            QPushButton:pressed {
                color: #990000;
            }
        )");
        delete_button->setToolTip(QObject::tr("Delete"));

        auto* button_container = new QWidget();
        auto* button_layout = new QHBoxLayout(button_container);
        button_layout->setContentsMargins(8, 0, 8, 0);
        button_layout->setAlignment(Qt::AlignCenter);
        button_layout->addWidget(delete_button);
        server_table_->setCellWidget(new_row, 3, button_container);

        QMessageBox::information(this, QObject::tr("Save Successful"),
            QObject::tr("Data has been successfully saved."));
      } else {
        QMessageBox::critical(this, QObject::tr("Save Failed"),
            QObject::tr("An error occurred while saving the data."));
      }
    } catch (const std::exception& err) {
      QMessageBox::critical(this, QObject::tr("Error!"), err.what());
    }
  }
  UpdateServerTableVisibility();
}

void SettingsWidget::onRemoveServer(int row) {
  if (row >= 0 && row < server_table_->rowCount() && server_table_ != nullptr) {
    server_table_->removeRow(row);
    settings_->RemoveServer(row);
    QMessageBox::information(this, QObject::tr("Delete Successful"),
        QObject::tr("The data has been successfully removed"));
  }
  UpdateServerTableVisibility();
}

void SettingsWidget::closeEvent(QCloseEvent* event) {
  onExit();
  event->accept();  // Accept the event to proceed with the closing
}

void SettingsWidget::onLanguageChanged(const QString&) {
  // set language
  settings_->SetLanguage(language_combo_box_->currentText());
  fptn::gui::SetTranslation(settings_->LanguageCode());
  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }

  setWindowTitle(QObject::tr("Settings"));
  if (tab_widget_) {
    tab_widget_->setTabText(0, QObject::tr("Settings"));
    tab_widget_->setTabText(1, QObject::tr("Routing"));
    tab_widget_->setTabText(2, QObject::tr("About"));
  }
  if (language_label_) {
    language_label_->setText(QObject::tr("Language"));
  }
  if (enable_ad_block_label_) {
    enable_ad_block_label_->setText(QObject::tr("Block ads"));
  }
  if (interface_label_) {
    interface_label_->setText(QObject::tr("Network Interface (adapter)"));
  }
  if (gateway_label_) {
    gateway_label_->setText(
        QObject::tr("Gateway IP Address (typically your router's address)"));
  }
  if (server_table_) {
    server_table_->setHorizontalHeaderLabels(
        {QObject::tr("Service name"), QObject::tr("Token updated"),
            QObject::tr("User"), QObject::tr("Action")});
    for (int row = 0; row < server_table_->rowCount(); ++row) {
      QWidget* button_container = server_table_->cellWidget(row, 3);
      if (button_container == nullptr) {
        continue;
      }
      auto* delete_button = button_container->findChild<QPushButton*>();
      if (delete_button != nullptr) {
        delete_button->setToolTip(QObject::tr("Delete"));
      }
    }
  }
  if (load_new_token_button_) {
    load_new_token_button_->setText("  " + QObject::tr("Add token") + "  ");
  }
  if (exit_button_) {
    exit_button_->setText("  " + QObject::tr("Close") + "  ");
  }
  if (gateway_auto_checkbox_) {
    gateway_auto_checkbox_->setText(QObject::tr("Auto"));
  }
  if (custom_dns_auto_checkbox_) {
    custom_dns_auto_checkbox_->setText(QObject::tr("Auto"));
  }
  // AUTOSTART (show only for Linux)
#ifdef __linux__
  if (autostart_label_) {
    autostart_label_->setText(QObject::tr("Autostart"));
  }
#endif

  if (connection_strategy_label_) {
    connection_strategy_label_->setText(QObject::tr("Connection strategy"));
  }
  if (connection_strategy_combo_box_) {
    const QString current_strategy = settings_->ConnectionStrategy();
    connection_strategy_combo_box_->clear();
    connection_strategy_combo_box_->addItem(QObject::tr("Rolling tunnel"),
        SettingsModel::kConnectionStrategyRolling);
    connection_strategy_combo_box_->addItem(QObject::tr("Dual rolling tunnel"),
        SettingsModel::kConnectionStrategyDual);
    connection_strategy_combo_box_->addItem(
        QObject::tr("Triple rolling tunnel"),
        SettingsModel::kConnectionStrategyTriple);

    const int strategy_index =
        connection_strategy_combo_box_->findData(current_strategy);
    connection_strategy_combo_box_->setCurrentIndex(
        strategy_index >= 0 ? strategy_index : 0);
  }

  // Bypass blocking
  if (bypass_method_label_) {
    bypass_method_label_->setText(QObject::tr("Bypass blocking method"));
  }

  if (bypass_method_combo_box_) {
    FillBypassMethodComboBox();
  }

  if (sni_label_) {
    if (settings_->BypassMethod() != SettingsModel::kBypassMethodSni) {
      sni_label_->setText(QObject::tr("Fake domain to bypass blocking"));
    }
  }
  if (sni_autoscan_button_) {
    sni_autoscan_button_->setText(QObject::tr("Autoscan SNI"));
  }
  if (sni_import_button_) {
    sni_import_button_->setText(QObject::tr("Import SNI file"));
  }

  // Routing tab
  if (enable_dns_management_label_) {
    enable_dns_management_label_->setText(
        QObject::tr("Enable advanced DNS management"));
  }
  if (enable_dns_management_info_label_) {
    enable_dns_management_info_label_->setText(QObject::tr(
        "Enables advanced DNS configuration to prevent leaks. "
        "Recommended when using split tunneling. Use with caution!"));
  }
  if (advanced_routing_button_) {
    advanced_routing_button_->setText(QObject::tr("Advanced"));
  }
  if (blacklist_domains_label_) {
    blacklist_domains_label_->setText(QObject::tr("Blacklist domains"));
  }
  if (blacklist_domains_info_label_) {
    blacklist_domains_info_label_->setText(
        QObject::tr("Completely block access to the main domain AND all its "
                    "subdomains. Format: example.com (one per line)"));
  }
  if (blacklist_domains_text_edit_) {
    blacklist_domains_text_edit_->setPlaceholderText(
        QObject::tr("example.com\nanother.com"));
  }

  if (exclude_tunnel_networks_label_) {
    exclude_tunnel_networks_label_->setText(
        QObject::tr("Exclude tunnel networks"));
  }
  if (exclude_tunnel_networks_info_label_) {
    exclude_tunnel_networks_info_label_->setText(QObject::tr(
        "Networks that always bypass VPN tunnel. "
        "Traffic to these networks goes directly, never through VPN"));
  }

  if (include_tunnel_networks_label_) {
    include_tunnel_networks_label_->setText(
        QObject::tr("Include tunnel networks"));
  }
  if (include_tunnel_networks_info_label_) {
    include_tunnel_networks_info_label_->setText(
        QObject::tr("Networks that always use VPN tunnel. "
                    "Traffic to these networks always goes through VPN"));
  }
  if (include_tunnel_networks_text_edit_) {
    include_tunnel_networks_text_edit_->setPlaceholderText(
        QObject::tr("192.168.99.0/24"));
  }

  if (enable_split_tunnel_label_) {
    enable_split_tunnel_label_->setText(QObject::tr("Enable split tunnel"));
  }
  if (enable_split_tunnel_info_label_) {
    enable_split_tunnel_info_label_->setText(
        QObject::tr("When enabled, you can configure which sites use VPN and "
                    "which go directly."));
  }

  if (split_tunnel_mode_label_) {
    split_tunnel_mode_label_->setText(QObject::tr("Split tunnel mode"));
  }
  if (split_tunnel_mode_info_label_) {
    split_tunnel_mode_info_label_->setText(
        QObject::tr("Defines traffic routing strategy for split tunneling."));
  }
  if (split_tunnel_mode_combo_box_) {
    QString current_mode = split_tunnel_mode_combo_box_->currentText();
    split_tunnel_mode_combo_box_->clear();
    split_tunnel_mode_combo_box_->addItem(
        QObject::tr("Exclude"), SettingsModel::kSplitTunnelModeExclude);
    split_tunnel_mode_combo_box_->addItem(
        QObject::tr("Include"), SettingsModel::kSplitTunnelModeInclude);

    if (current_mode == QObject::tr("Include") ||
        current_mode == SettingsModel::kSplitTunnelModeInclude) {
      split_tunnel_mode_combo_box_->setCurrentText(QObject::tr("Include"));
    } else {
      split_tunnel_mode_combo_box_->setCurrentText(QObject::tr("Exclude"));
    }
  }

  if (split_tunnel_domains_label_ && split_tunnel_domains_info_label_) {
    if (settings_->SplitTunnelMode() ==
        SettingsModel::kSplitTunnelModeInclude) {
      split_tunnel_domains_label_->setText(
          QObject::tr("Domains to route through VPN"));
      split_tunnel_domains_info_label_->setText(QObject::tr(
          "List domains that should use VPN tunnel. Only these domains will "
          "go through VPN, all other traffic bypasses VPN"));
    } else {
      split_tunnel_domains_label_->setText(
          QObject::tr("Domains to bypass VPN"));
      split_tunnel_domains_info_label_->setText(
          QObject::tr("List domains that should bypass VPN tunnel. These "
                      "domains will go directly, all other traffic uses VPN"));
    }
  }
  if (split_tunnel_domains_text_edit_) {
    split_tunnel_domains_text_edit_->setPlaceholderText(
        QObject::tr("com\nanother.com\nsub.domainname.com"));
  }

  if (custom_dns_label_) {
    custom_dns_label_->setText(QObject::tr("Custom DNS"));
  }

  // about
  if (version_label_) {
    version_label_->setText(
        QString(QObject::tr("Version") + ": %1").arg(FPTN_VERSION));
  }
  if (project_info_label_) {
    project_info_label_->setText(QObject::tr("FPTN_DESCRIPTION"));
  }
  if (website_link_label_) {
    website_link_label_->setText(QObject::tr("FPTN_WEBSITE_DESCRIPTION"));
  }
  if (telegram_group_label_) {
    telegram_group_label_->setText(QObject::tr("FPTN_TELEGRAM_DESCRIPTION"));
  }
  // sponsors section
  if (boosty_link_label_) {
    boosty_link_label_->setText(
        QObject::tr("Support the project on") +
        " <a href=\"https://boosty.to/fptn\">Boosty</a>");
  }
  if (sponsors_label_) {
    sponsors_label_->setText(QObject::tr("Project Sponsors"));
  }
}

void SettingsWidget::onInterfaceChanged(const QString&) {
  settings_->SetUsingNetworkInterface(interface_combo_box_->currentText());
  if (!settings_->Save()) {
    QMessageBox::critical(this, QObject::tr("Save Failed"),
        QObject::tr("An error occurred while saving the data."));
  }
}

void SettingsWidget::onAutostartChanged(bool checked) {
  if (checked) {
    fptn::gui::autostart::enable();
    settings_->SetAutostart(true);
  } else {
    fptn::gui::autostart::disable();
    settings_->SetAutostart(false);
  }
}

void SettingsWidget::onAutoGatewayChanged(bool checked) {
  if (checked) {
    gateway_line_edit_->setDisabled(true);
    gateway_line_edit_->setText("");
    gateway_line_edit_->setPlaceholderText("");
    settings_->SetGatewayIp("auto");
  } else {
    gateway_line_edit_->setEnabled(true);
    gateway_line_edit_->setPlaceholderText("192.168.1.1");
  }
}
void SettingsWidget::onAutoCustomDnsChanged(bool checked) {
  if (checked) {
    custom_dns_line_edit_->setDisabled(true);
    custom_dns_line_edit_->setText("");
    custom_dns_line_edit_->setPlaceholderText("");
    settings_->SetCustomDns("");
  } else {
    custom_dns_line_edit_->setEnabled(true);
    custom_dns_line_edit_->setPlaceholderText("8.8.8.8");
  }
}
void SettingsWidget::onBypassMethodChanged(const QString& method) {
  const bool is_reality_mode =
      method != SettingsModel::kBypassMethodObfuscation;

  // Show/hide SNI field
  sni_label_->setVisible(is_reality_mode);
  sni_line_edit_->setVisible(is_reality_mode);

  // Show/hide SNI files section based on mode
  sni_files_list_widget_->setVisible(is_reality_mode);
  sni_autoscan_button_->setVisible(is_reality_mode);
  sni_import_button_->setVisible(is_reality_mode);

  if (is_reality_mode) {
    grid_layout_->addWidget(sni_label_, 8, 0, Qt::AlignLeft | Qt::AlignVCenter);
    grid_layout_->addWidget(sni_line_edit_, 8, 1);
    grid_layout_->addLayout(sni_buttons_layout_, 9, 0);
    grid_layout_->addWidget(sni_files_list_widget_, 9, 1);
  } else {
    grid_layout_->removeWidget(sni_label_);
    grid_layout_->removeWidget(sni_line_edit_);
    grid_layout_->removeItem(sni_buttons_layout_);
    grid_layout_->removeWidget(sni_files_list_widget_);
  }

  settings_->SetBypassMethod(method);

  if (sni_label_) {
    if (settings_->BypassMethod() != SettingsModel::kBypassMethodSni) {
      sni_label_->setText(QObject::tr("Fake domain to bypass blocking"));
    }
  }
}

void SettingsWidget::UpdateSniFilesList() {
  sni_files_list_widget_->clear();

  auto files = settings_->SniManager()->SniFileList();
  for (const auto& file : files) {
    QString file_name = QString::fromStdString(file);

    auto* item_widget = new QWidget(this);
    auto* layout = new QHBoxLayout(item_widget);
    layout->setContentsMargins(10, 5, 10, 5);
    layout->setSpacing(10);

    auto* name_label = new QLabel(file_name);
    name_label->setStyleSheet("QLabel { font-weight: bold; }");
    name_label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    layout->addWidget(name_label);

    item_widget->setLayout(layout);

    auto* item = new QListWidgetItem(sni_files_list_widget_);
    item->setSizeHint(item_widget->sizeHint());
    sni_files_list_widget_->setItemWidget(item, item_widget);
  }

  if (files.empty()) {
    auto* empty_item = new QListWidgetItem(
        QObject::tr("No SNI files imported"), sni_files_list_widget_);
    empty_item->setFlags(empty_item->flags() & ~Qt::ItemIsEnabled);
    empty_item->setTextAlignment(Qt::AlignCenter);
  }
}

void SettingsWidget::onImportSniFile() {
  QString file_path =
      QFileDialog::getOpenFileName(this, QObject::tr("Select SNI file"), "",
          QObject::tr("SNI files (*.sni);;All files (*)"));

  if (!file_path.isEmpty()) {
    QFileInfo file_info(file_path);
    QString file_name = file_info.fileName();

    auto existing_files = settings_->SniManager()->SniFileList();
    bool file_exists = false;
    for (const auto& existing_file : existing_files) {
      if (QString::fromStdString(existing_file) == file_name) {
        file_exists = true;
        break;
      }
    }

    if (file_exists) {
      QMessageBox::StandardButton reply = QMessageBox::question(this,
          QObject::tr("File exists"),
          QObject::tr("File \"%1\" already exists. Overwrite?").arg(file_name),
          QMessageBox::Yes | QMessageBox::No);
      if (reply != QMessageBox::Yes) {
        return;
      }
    }

    if (settings_->SniManager()->AddSniFile(file_path.toStdString())) {
      UpdateSniFilesList();
      QMessageBox::information(this, QObject::tr("Success"),
          QObject::tr("SNI file imported successfully"));
    } else {
      QMessageBox::warning(
          this, QObject::tr("Error"), QObject::tr("Failed to import SNI file"));
    }
  }
}

void SettingsWidget::onAutoscanClicked() {
  SniAutoscanDialog dialog(settings_, this);
  dialog.exec();
  sni_line_edit_->setText(settings_->SNI());
}

void SettingsWidget::UpdateServerTableVisibility() {
  if (server_table_) {
    server_table_->setVisible(true);
  }
}
