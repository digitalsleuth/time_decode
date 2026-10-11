import base64
import csv
import os
import sys
from datetime import datetime as dt, timezone
from weakref import WeakKeyDictionary
from zoneinfo import ZoneInfo as tzone
from PyQt6.QtCore import (
    QRect,
    Qt,
    QMetaObject,
    QCoreApplication,
    QDate,
    QSettings,
    QSize,
)
from PyQt6.QtGui import (
    QAction,
    QPixmap,
    QIcon,
    QFont,
    QKeySequence,
    QColor,
    QPainter,
    QActionGroup,
)
from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QDateTimeEdit,
    QComboBox,
    QPushButton,
    QRadioButton,
    QApplication,
    QMenu,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QSizePolicy,
    QMainWindow,
    QStyle,
    QFileDialog,
)
from time_decode.scheme import CLASSIC, available_schemes, build_palette, default_scheme
from time_decode.time_decode import (
    __appname__,
    __author__,
    __date__,
    __source__,
    __version__,
    common_timezone_offsets,
    convert_timezone,
    date_formats,
    from_all,
    generate_csv,
    handle,
    result_year,
    set_date_format,
    single_funcs,
    to_timestamps,
    ts_types,
    type_groups,
)


def main_stylesheet(scheme):
    return f"""
        QMainWindow {{
            background-color: {scheme.window}; color: {scheme.text};
        }}
        QLineEdit {{
            background-color: {scheme.base}; color: {scheme.text};
        }}
        QDateTimeEdit {{
            background-color: {scheme.base}; color: {scheme.text};
        }}
        QMenu {{
            background-color: {scheme.window}; color: {scheme.text}; border: 1px solid {scheme.text}; margin: 0;
        }}
        QMenu::item {{
            background-color: {scheme.window}; color: {scheme.text}; margin: 0; padding: 4px 20px 4px 20px;
        }}
        QMenu::item:selected {{
            background-color: {scheme.highlight}; color: {scheme.highlight_text}; margin: 0; padding: 4px 20px 4px 20px;
        }}
        QMenuBar {{
            background-color: {scheme.window}; color: {scheme.text};
        }}
        QMenuBar::item {{
            background-color: {scheme.window}; color: {scheme.text};
        }}
        QMenuBar::item:selected {{
            background-color: {scheme.highlight}; color: {scheme.highlight_text};
        }}
        """


STYLES = {
    "main": main_stylesheet,
    "window_bg": lambda s: f"background-color: {s.window};",
    "plain": lambda s: f"background-color: {s.window}; color: {s.text};",
    "popup_frame": lambda s: f"border: none; selection-background-color: {s.highlight};",
    "calendar": lambda s: f"alternate-background-color: {s.alternate}; background-color: {s.base}; color: {s.text};",
    "combo": lambda s: f"combobox-popup: 0; background-color: {s.base}; color: {s.text};",
    "table_setup": lambda s: f"border: none; background-color: {s.base}; color: {s.text}; font-size: 10;",
    "table_reset": lambda s: "border: none",
    "icon_button": lambda s: f"background-color: {s.window}; color: {s.text}; border: 0;",
    "table": lambda s: f"""
            border: none;
            alternate-background-color: {s.alternate};
            background-color: {s.base};
            color: {s.text};
            selection-background-color: {s.highlight};
            """,
    "csv_combo": lambda s: f"""
            combobox-popup: 0;
            background-color: {s.base};
            color: {s.text};
            selection-background-color: {s.base};
            selection-color: {s.text};
            """,
    "csv_window": lambda s: f"background: {s.window}; color: {s.text};",
    "popup_table": lambda s: f"""
                border: none; alternate-background-color: {s.alternate};
                background-color: {s.base}; color: {s.text};
                """,
}

TYPE_KEYS = {}
for _key, _data in ts_types.items():
    TYPE_KEYS.setdefault(_data.ts_type, _key)

active = CLASSIC
styled = WeakKeyDictionary()
original_palette = []


def style(widget, kind):
    styled[widget] = kind
    widget.setStyleSheet(STYLES[kind](active))


def result_rows(results, highlight):
    this_yr = dt.now(timezone.utc).year
    years = range(this_yr - 5, this_yr + 5)
    return [
        (
            ts_types[ts_type][0],
            ts_types[ts_type][1],
            result,
            highlight and result_year(result) in years,
        )
        for ts_type, result in results.items()
    ]


def fill_table(table, rows):
    alignment = int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    table.setUpdatesEnabled(False)
    table.setRowCount(len(rows))
    for row, (name, tooltip, value, matched) in enumerate(rows):
        for column, (text, tip) in enumerate(((name, tooltip), (value, None))):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            if tip is not None:
                item.setToolTip(tip)
            item.setTextAlignment(alignment)
            if matched:
                item.setBackground(QColor(active.match))
                item.setForeground(QColor(active.match_text))
            table.setItem(row, column, item)
    table.setUpdatesEnabled(True)


def tinted(icon, color, size):
    pixmap = icon.pixmap(size)
    painter = QPainter(pixmap)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return QIcon(pixmap)


def apply_scheme(scheme):
    global active
    active = scheme
    TimeDecodeGui.stylesheet = main_stylesheet(scheme)
    application = QApplication.instance()
    if application is not None:
        if not original_palette:
            original_palette.append(application.palette())
        application.setPalette(
            original_palette[0]
            if scheme == CLASSIC
            else build_palette(scheme, original_palette[0])
        )
    for widget, kind in list(styled.items()):
        widget.setStyleSheet(STYLES[kind](scheme))


SETTINGS_ORGANIZATION = "digitalsleuth"
SETTINGS_APPLICATION = "time_decode"
THEME_KEY = "appearance/theme"


def settings():
    return QSettings(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        SETTINGS_ORGANIZATION,
        SETTINGS_APPLICATION,
    )


def saved_scheme():
    name = settings().value(THEME_KEY)
    return (
        available_schemes().get(name, default_scheme())
        if isinstance(name, str)
        else default_scheme()
    )


def save_scheme_name(name):
    store = settings()
    store.setValue(THEME_KEY, name)
    store.sync()


def restore_scheme():
    scheme = saved_scheme()
    if scheme != CLASSIC:
        apply_scheme(scheme)


class NewWindow(QWidget):
    """This class sets the structure for a new window"""

    def __init__(self, parent=None):
        """Sets up the new window table and context menu"""
        super().__init__(parent)
        if parent:
            self.setPalette(parent.palette())
            self.setFont(parent.font())
        style(self, "window_bg")
        layout = QVBoxLayout(self)
        self.window_label = QLabel(self)
        self.output_table = QTableWidget(self)
        self.output_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        style(self.output_table, "popup_frame")
        self.output_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.context_menu = ContextMenu(self.output_table)
        self.output_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.output_table.customContextMenuRequested.connect(
            self.context_menu.show_context_menu
        )
        layout.addWidget(self.output_table)
        layout.addWidget(self.window_label)
        self.stylesheet = TimeDecodeGui.stylesheet
        self.setLayout(layout)

    def key_press_event(self, event):
        """Sets the Ctrl+C KeyPress for the window"""
        if event.matches(QKeySequence.StandardKey.Copy):
            self.context_menu.copy()
        else:
            super().key_press_event(event)


class CsvWindow(QWidget):
    """This class sets the structure for a new window"""

    def __init__(
        self,
        ts_formats: QComboBox,
        time_zones: QComboBox,
        dt_formats: QComboBox,
        parent=None,
    ):
        """Sets up the new window table and context menu"""
        super().__init__(parent)
        if parent:
            self.setPalette(parent.palette())
            self.setFont(parent.font())
        self.window_label = QLabel(self)
        self.output_table = QTableWidget(self)
        self.ts_formats = QComboBox(self)
        self.time_zones = QComboBox(self)
        self.dt_formats = QComboBox(self)
        for i in range(ts_formats.count()):
            self.ts_formats.addItem(ts_formats.itemText(i), ts_formats.itemData(i))
        for i in range(time_zones.count()):
            self.time_zones.addItem(time_zones.itemText(i), time_zones.itemData(i))
        for i in range(dt_formats.count()):
            self.dt_formats.addItem(dt_formats.itemText(i), dt_formats.itemData(i))
        self.output_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.output_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )


class AboutWindow(QWidget):
    """Sets the structure for the About window"""

    def __init__(self):
        super().__init__()
        layout = QGridLayout()
        self.about_label = QLabel()
        self.url_label = QLabel()
        self.logo_label = QLabel()
        spacer = QLabel()
        layout.addWidget(self.about_label, 0, 0)
        layout.addWidget(spacer, 0, 1)
        layout.addWidget(self.url_label, 1, 0)
        layout.addWidget(self.logo_label, 0, 2)
        style(self, "plain")
        self.setFixedHeight(100)
        self.setFixedWidth(350)
        self.setLayout(layout)


class ContextMenu:
    """Shows a context menu for a QTableWidget"""

    def __init__(self, tbl_widget):
        """Associate the tbl_widget variable"""
        self.tbl_widget = tbl_widget

    def show_context_menu(self, pos):
        """Sets the context menu structure and style"""
        stylesheet = TimeDecodeGui.stylesheet
        context_menu = QMenu(self.tbl_widget)
        copy_event = context_menu.addAction("Copy")
        copy_event.setShortcut(QKeySequence("Ctrl+C"))
        copy_event.setShortcutVisibleInContextMenu(True)
        context_menu.setStyleSheet(stylesheet)
        copy_event.triggered.connect(self.copy)
        context_menu.exec(self.tbl_widget.mapToGlobal(pos))

    def copy(self):
        """Sets up the Copy option for the context menu"""
        selected = self.tbl_widget.selectedItems()
        if selected:
            clipboard = QApplication.clipboard()
            rows = {}
            for item in selected:
                rows.setdefault(item.row(), []).append(item.text())
            text = (
                "\n".join(
                    "\t".join(rows.get(row, ()))
                    for row in range(min(rows), max(rows) + 1)
                )
            ).rstrip()
            text = text.lstrip()
            clipboard.setText(text)


class UiMainWindow:
    """Sets the structure for the main user interface"""

    def __init__(self):
        super().__init__()
        self.window_width = 490
        self.window_height = 130
        self.text_font = QFont()
        self.text_font.setPointSize(9)
        self.results = {}
        self.examples_window = None
        self.new_window = None
        self.new_window_icon = None
        self.timestamp_text = None
        self.date_time = None
        self.calendar_widget = None
        self.now_button = None
        self.update_button = None
        self.button_layout = None
        self.calendar_buttons = None
        self.timestamp_formats = None
        self.time_zone_offsets = None
        self.output_table = None
        self.context_menu = None
        self.guess_button = None
        self.to_all_button = None
        self.encode_radio = None
        self.decode_radio = None
        self.go_button = None
        self.new_window_button = None
        self.menu_bar = None
        self.file_menu = None
        self.exit_action = None
        self.view_menu = None
        self.view_action = None
        self.theme_menu = None
        self.theme_group = None
        self.theme_actions = {}
        self.schemes = {}
        self.help_menu = None
        self.about_action = None
        self.msg_box = None
        self.about_window = None
        self.logo = None
        self.timestamp_count_label = None
        self.dt_format_combo = None
        self.decode_from_file_button = None
        self.selected_header = None
        self.csv_path = None
        self.csv_content_window = None
        self.csv_go_button = None
        self.csv_decode_action = None
        self.select_new_csv = None
        self.csv_close_button = None
        self.__fmt__ = "%Y-%m-%d %H:%M:%S.%f"
        self.screen_layout = QApplication.primaryScreen().availableGeometry()
        self.center_x = (self.screen_layout.width() // 2) - (self.window_width // 2)
        self.center_y = (self.screen_layout.height() // 2) - (self.window_height // 2)

    def setup_ui(self, main_window):
        """Sets up the core UI"""
        if not main_window.objectName():
            main_window.setObjectName(__appname__)
        main_window.setFixedWidth(self.window_width)
        main_window.setMinimumHeight(self.window_height)
        style(main_window, "main")
        main_window.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        main_window.setWindowFlags(
            main_window.windowFlags() & ~Qt.WindowType.WindowMaximizeButtonHint
        )
        main_window.move(self.center_x, self.center_y)
        self.timestamp_text = QLineEdit(main_window)
        self.timestamp_text.setObjectName("timestamp_text")
        self.timestamp_text.setGeometry(QRect(10, 30, 225, 22))
        self.timestamp_text.setHidden(False)
        self.timestamp_text.setEnabled(True)
        style(self.timestamp_text, "main")
        self.timestamp_text.setFont(self.text_font)
        self.timestamp_text.setToolTip(
            "Enter your timestamp. To verify your timestamp format, select 'View -> Examples'."
        )
        utc_time = dt.now(timezone.utc)
        self.date_time = QDateTimeEdit(main_window)
        self.date_time.setObjectName("date_time")
        self.date_time.setDisplayFormat("yyyy-MM-dd HH:mm:ss.zzz")
        self.date_time.setGeometry(QRect(10, 30, 225, 22))
        self.date_time.setDateTime(utc_time)
        self.date_time.setCalendarPopup(True)
        self.date_time.calendarWidget().setFixedHeight(220)
        self.date_time.calendarWidget().setGridVisible(True)
        self.date_time.setHidden(True)
        self.date_time.setEnabled(False)
        style(self.date_time, "main")
        self.calendar_widget = self.date_time.calendarWidget()
        style(self.calendar_widget, "calendar")
        self.date_time.setFont(self.text_font)
        self.date_time.calendarWidget().setFont(self.text_font)
        self.date_time.setToolTip(
            "Enter your date/time as 'YYYY-mm-dd HH:MM:SS.fff' and only 3 digits for milliseconds."
        )
        self.now_button = QPushButton("&Now", clicked=self.set_now)
        self.now_button.setFont(self.text_font)
        self.update_button = QPushButton(
            "&Update Time Zones", clicked=self.update_timezones
        )
        self.update_button.setFont(self.text_font)
        self.button_layout = QHBoxLayout()
        self.button_layout.addWidget(self.now_button)
        self.button_layout.addWidget(self.update_button)
        self.calendar_buttons = self.date_time.calendarWidget().layout()
        self.calendar_buttons.addLayout(self.button_layout)
        self.timestamp_formats = QComboBox(main_window)
        self.timestamp_formats.setObjectName("timestamp_formats")
        self.timestamp_formats.setGeometry(QRect(10, 60, 225, 22))
        style(self.timestamp_formats, "combo")
        self.timestamp_formats.view().setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.timestamp_formats.setFont(self.text_font)
        types = {}
        for _, this_type in ts_types.items():
            types[this_type[0]] = this_type[1]
        types = dict(sorted(types.items(), key=lambda item: item[0].casefold()))
        for k, v in enumerate(types.items()):
            self.timestamp_formats.addItem(v[0])
            self.timestamp_formats.setItemData(k, v[1], Qt.ItemDataRole.ToolTipRole)
        self.time_zone_offsets = QComboBox(main_window)
        self.time_zone_offsets.setObjectName("time_zone_offsets")
        self.time_zone_offsets.setGeometry(QRect(10, 90, 305, 22))
        style(self.time_zone_offsets, "combo")
        self.time_zone_offsets.view().setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.time_zone_offsets.setFont(self.text_font)
        try:
            dt_obj = dt.fromisoformat(self.date_time.text()).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            dt_obj = dt.strptime(self.date_time.text(), self.__fmt__).replace(
                tzinfo=timezone.utc
            )
        ts_offsets = common_timezone_offsets(dt_obj)
        for k, v in enumerate(ts_offsets):
            self.time_zone_offsets.addItem(f"{v[0]} {v[1]}")
            self.time_zone_offsets.setItemData(k, v[1], Qt.ItemDataRole.ToolTipRole)
        self.time_zone_offsets.setEnabled(True)
        self.time_zone_offsets.setHidden(False)
        tz_tooltip = (
            "Time Zones in the drop-down box are displayed based on the current date/time.\n"
            "The actual UTC Offset (whether observing DST or not) will be calculated\naccordingly"
            " when generating output.\n\n"
            "For example: Europe/Amsterdam time zone is UTC+01:00 before 29 March 2026 at 2AM,\n"
            "then it is UTC+02:00 until 29 October 2026 at 3AM.\n\n"
            "If YOUR current date/time falls between these two times, the time zone will display "
            "UTC+02:00.\n"
            "Otherwise, it will display UTC+01:00.\n\nThe output will adjust based on the date/time"
            " value provided or determined."
        )
        self.time_zone_offsets.setToolTip(tz_tooltip)
        self.output_table = QTableWidget(main_window)
        self.output_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.output_table.setGeometry(QRect(10, 120, 440, 22))
        style(self.output_table, "table_setup")
        self.output_table.setVisible(False)
        self.output_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOn
        )
        self.output_table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.context_menu = ContextMenu(self.output_table)
        self.output_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.output_table.customContextMenuRequested.connect(
            self.context_menu.show_context_menu
        )
        self.output_table.setFont(self.text_font)
        self.guess_button = QPushButton(main_window)
        self.guess_button.setObjectName("guess_button")
        self.guess_button.setEnabled(True)
        self.guess_button.setHidden(False)
        self.guess_button.setGeometry(QRect(245, 30, 70, 22))
        style(self.guess_button, "plain")
        self.guess_button.setFont(self.text_font)
        self.guess_button.clicked.connect(self.guess_decode)
        self.guess_button.setToolTip(
            "Run the current timestamp through all functions to 'Guess' the format."
        )
        self.to_all_button = QPushButton(main_window)
        self.to_all_button.setObjectName("to_all_button")
        self.to_all_button.setEnabled(False)
        self.to_all_button.setHidden(True)
        self.to_all_button.setGeometry(QRect(245, 30, 70, 22))
        style(self.to_all_button, "plain")
        self.to_all_button.setFont(self.text_font)
        self.to_all_button.clicked.connect(self.encode_toall)
        self.to_all_button.setToolTip(
            "Convert the selected date/time value to all timestamp formats."
        )
        self.encode_radio = QRadioButton(main_window)
        self.encode_radio.setObjectName("encode_radio")
        self.encode_radio.setGeometry(QRect(400, 30, 72, 20))
        style(self.encode_radio, "plain")
        self.encode_radio.setFont(self.text_font)
        self.encode_radio.toggled.connect(self._encode_select)
        self.decode_radio = QRadioButton(main_window)
        self.decode_radio.setObjectName("decode_radio")
        self.decode_radio.setGeometry(QRect(325, 30, 72, 20))
        self.decode_radio.setChecked(True)
        style(self.decode_radio, "plain")
        self.decode_radio.setFont(self.text_font)
        self.decode_radio.toggled.connect(self._decode_select)
        self.decode_from_file_button = QPushButton(main_window)
        self.decode_from_file_button.setObjectName("decode_from_file_button")
        self.decode_from_file_button.setEnabled(True)
        self.decode_from_file_button.setHidden(False)
        self.decode_from_file_button.setGeometry(QRect(322, 60, 72, 22))
        style(self.decode_from_file_button, "plain")
        self.decode_from_file_button.setFont(self.text_font)
        self.decode_from_file_button.clicked.connect(self.csv_decode)
        self.decode_from_file_button.setToolTip(
            "Decode timestamps from a CSV/TXT file."
        )
        self.dt_format_combo = QComboBox(main_window)
        self.dt_format_combo.setObjectName("dt_format_combo")
        self.dt_format_combo.setEnabled(True)
        self.dt_format_combo.setHidden(False)
        self.dt_format_combo.setFont(self.text_font)
        self.dt_format_combo.setGeometry(QRect(400, 60, 70, 22))
        for k, v in enumerate(date_formats.items()):
            self.dt_format_combo.addItem(f"{v[0]}")
            self.dt_format_combo.setItemData(
                k, v[1].replace("%", ""), Qt.ItemDataRole.ToolTipRole
            )
        style(self.dt_format_combo, "plain")
        self.dt_format_combo.setToolTip("Choose your desired date/time format.")
        self.go_button = QPushButton(main_window)
        self.go_button.setObjectName("go_button")
        self.go_button.setGeometry(QRect(245, 60, 70, 22))
        style(self.go_button, "plain")
        self.go_button.setFont(self.text_font)
        self.go_button.clicked.connect(self.go_function)
        self.go_button.setToolTip("Convert to/from the timestamp selected to the left.")
        new_window_pixmap = QStyle.StandardPixmap.SP_ArrowUp
        icon = main_window.style().standardIcon(new_window_pixmap)
        self.new_window_button = QPushButton(main_window)
        self.new_window_button.setObjectName("new_window_button")
        self.new_window_button.setGeometry(QRect(325, 90, 22, 22))
        style(self.new_window_button, "icon_button")
        self.new_window_button.setFont(self.text_font)
        self.new_window_icon = icon
        self._set_new_window_icon()
        self.new_window_button.setIconSize(QSize(22, 22))
        self.new_window_button.setToolTip("Open results in a new window")
        self.new_window_button.clicked.connect(self._new_window)
        if os.sys.platform == "linux":
            vert = 415
        else:
            vert = 370
        self.timestamp_count_label = QLabel(main_window)
        self.timestamp_count_label.setGeometry(QRect(vert, 94, 90, 22))
        style(self.timestamp_count_label, "plain")
        self.timestamp_count_label.setFont(self.text_font)
        self.timestamp_count_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.retranslate_ui(main_window)
        QMetaObject.connectSlotsByName(main_window)

    def retranslate_ui(self, main_window):
        """Retranslate the Ui"""
        _translate = QCoreApplication.translate
        main_window.setWindowTitle(_translate("main_window", __appname__, None))
        self.date_time.setDisplayFormat(
            _translate("main_window", "yyyy-MM-dd HH:mm:ss.zzz", None)
        )
        self.timestamp_text.setPlaceholderText(
            _translate("main_window", "Timestamp", None)
        )
        self.guess_button.setText(_translate("main_window", "Guess", None))
        self.to_all_button.setText(_translate("main_window", "To All", None))
        self.encode_radio.setText(_translate("main_window", "Encode", None))
        self.decode_radio.setText(_translate("main_window", "Decode", None))
        self.go_button.setText(_translate("main_window", "← From", None))
        self.decode_from_file_button.setText(
            _translate("main_window", "From file..", None)
        )
        self.new_window_button.setHidden(True)
        self.new_window_button.setEnabled(False)
        self._menu_bar()

    def set_now(self):
        """Sets the current date / time on the Calendar Widget"""
        today = QDate.currentDate()
        now = dt.now(timezone.utc)
        self.date_time.calendarWidget().setSelectedDate(today)
        self.date_time.setDateTime(now)

    def _theme_menu(self):
        self.schemes = available_schemes()
        self.theme_menu = self.view_menu.addMenu("&Theme")
        self.theme_menu.setFont(self.text_font)
        self.theme_group = QActionGroup(self)
        self.theme_group.setExclusive(True)
        self.theme_actions = {}
        for name, scheme in self.schemes.items():
            action = QAction(name, self)
            action.setCheckable(True)
            action.setChecked(scheme == active)
            action.setFont(self.text_font)
            action.triggered.connect(
                lambda checked, name=name, scheme=scheme: self._choose_scheme(
                    name, scheme
                )
            )
            self.theme_group.addAction(action)
            self.theme_menu.addAction(action)
            self.theme_actions[name] = action

    def _choose_scheme(self, name, scheme):
        self.set_scheme(scheme)
        save_scheme_name(name)

    def _set_new_window_icon(self):
        icon = self.new_window_icon
        if active != CLASSIC:
            icon = tinted(icon, active.text, QSize(22, 22))
        self.new_window_button.setIcon(icon)

    def set_scheme(self, scheme):
        apply_scheme(scheme)
        self._set_new_window_icon()
        for name, action in self.theme_actions.items():
            action.setChecked(self.schemes[name] == scheme)
        if self.results and not self.output_table.isHidden():
            self.display_output(self.results)
        if self.new_window is not None and self.new_window.isVisible():
            self._new_window()
        if self.examples_window is not None and self.examples_window.isVisible():
            self._examples()
        if self.about_window is not None and self.about_window.isVisible():
            self.about_window.close()
            self._about()

    def update_timezones(self):
        """Updates the time_zone_offsets combo box to reflect the selected Calendar date/time"""
        try:
            dt_obj = dt.fromisoformat(self.date_time.text()).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            dt_obj = dt.strptime(self.date_time.text(), self.__fmt__).replace(
                tzinfo=timezone.utc
            )
        ts_offsets = common_timezone_offsets(dt_obj)
        self.time_zone_offsets.clear()
        for k, v in enumerate(ts_offsets):
            self.time_zone_offsets.addItem(f"{v[0]} {v[1]}")
            self.time_zone_offsets.setItemData(k, v[1], Qt.ItemDataRole.ToolTipRole)

    def _decode_select(self):
        """Sets the structure for the decode radio button"""
        self.date_time.setHidden(True)
        self.date_time.setEnabled(False)
        self.timestamp_text.setHidden(False)
        self.timestamp_text.setEnabled(True)
        self.guess_button.setEnabled(True)
        self.guess_button.setHidden(False)
        self.to_all_button.setEnabled(False)
        self.to_all_button.setHidden(True)
        self.go_button.setText("← From")
        self.new_window_button.setHidden(True)
        self.new_window_button.setEnabled(False)
        self.timestamp_count_label.setText("")
        self.decode_from_file_button.setEnabled(True)
        self.decode_from_file_button.setHidden(False)
        self.dt_format_combo.setEnabled(True)
        self.dt_format_combo.setHidden(False)
        self._reset_table()

    def _encode_select(self):
        """Sets the structure for the encode radio button"""
        self.timestamp_text.setHidden(True)
        self.timestamp_text.setEnabled(False)
        self.date_time.setHidden(False)
        self.date_time.setEnabled(True)
        self.guess_button.setEnabled(False)
        self.guess_button.setHidden(True)
        self.to_all_button.setEnabled(True)
        self.to_all_button.setHidden(False)
        self.go_button.setText("← To")
        self.new_window_button.setHidden(True)
        self.new_window_button.setEnabled(False)
        self.timestamp_count_label.setText("")
        self.decode_from_file_button.setEnabled(False)
        self.decode_from_file_button.setHidden(True)
        self.dt_format_combo.setEnabled(False)
        self.dt_format_combo.setHidden(True)
        self._reset_table()

    def _reset_table(self):
        """Resets the GUI structure"""
        self.adjustSize()
        self.setFixedWidth(490)
        self.setFixedHeight(130)
        self.output_table.setVisible(False)
        self.output_table.clearContents()
        self.output_table.setColumnCount(0)
        self.output_table.setRowCount(0)
        self.output_table.reset()
        style(self.output_table, "table_reset")

    def _set_date_format(self, fmt):
        """Keeps the GUI and module-level date formats in sync"""
        set_date_format(fmt)
        self.__fmt__ = fmt

    def guess_decode(self):
        """Will take the provided timestamp and run it through the 'from_all' function"""
        self._set_date_format(date_formats[self.dt_format_combo.currentText()])
        timestamp = self.timestamp_text.text()
        selected_tz = self.time_zone_offsets.currentText()
        tz_name = " ".join(selected_tz.split(" ")[1:])
        if timestamp == "":
            self._msg_box("You must enter a timestamp!", "Info")
            return
        if "UTC - Default" in selected_tz:
            all_ts = from_all(timestamp)
        else:
            all_ts = from_all(timestamp, tz_name)
        results = {}
        for k, _ in all_ts.items():
            results[k] = f"{all_ts[k][0]} {all_ts[k][2]}"
        self.results = results
        self.display_output(results)

    def encode_toall(self):
        """Takes the date_time object, passes it to the to_timestamps function which encodes it"""
        dt_val = self.date_time.text()
        try:
            dt_obj = dt.fromisoformat(dt_val)
        except ValueError:
            dt_obj = dt.strptime(dt_val, self.__fmt__)
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        selected_tz = self.time_zone_offsets.currentText()
        if "UTC - Default" not in selected_tz:
            tz_name = " ".join(selected_tz.split(" ")[1:])
            tz = tzone(tz_name)
            dt_obj = dt_obj.replace(tzinfo=tz)
        results, _ = to_timestamps(dt_obj)
        self.results = results
        self.display_output(results)

    def display_output(self, ts_list):
        """Configures the output format for the provided values"""
        self._reset_table()
        tbl_fixed_width = 475
        col2_width = 235
        self_fixed_width = 490
        if os.sys.platform == "linux":
            tbl_fixed_width = 520
            col2_width = 280
            self_fixed_width = 535
        self.output_table.setVisible(True)
        self.output_table.setColumnCount(2)
        self.output_table.setAlternatingRowColors(True)
        style(self.output_table, "table")
        fill_table(
            self.output_table, result_rows(ts_list, self.decode_radio.isChecked())
        )
        self.output_table.horizontalHeader().setFixedHeight(1)
        self.output_table.verticalHeader().setFixedWidth(1)
        self.output_table.setFixedWidth(tbl_fixed_width)
        self.output_table.setColumnWidth(0, 220)
        self.output_table.setColumnWidth(1, col2_width)
        self.output_table.resizeRowsToContents()
        self.output_table.setShowGrid(True)
        total_row_height = sum(
            self.output_table.rowHeight(row)
            for row in range(self.output_table.rowCount())
        )
        self.output_table.setFixedHeight(400)
        if total_row_height > 500:
            self.setFixedHeight(540)
            self.output_table.verticalScrollBar().show()
        else:
            self.setFixedHeight(self.height() + int(total_row_height + 12))
            self.output_table.verticalScrollBar().hide()
        self.setFixedWidth(self_fixed_width)
        self.new_window_button.setEnabled(True)
        self.new_window_button.setHidden(False)
        if len(ts_list) > 1:
            txt = "timestamps"
        else:
            txt = "timestamp"
        self.timestamp_count_label.setText(f"{len(ts_list)} {txt}")

    def go_function(self):
        """The To/From button: converts a date/timestamp, depending on the selected radio button"""
        results = {}
        self._set_date_format(date_formats[self.dt_format_combo.currentText()])
        ts_format = self.timestamp_formats.currentText()
        try:
            ts_date = dt.fromisoformat(self.date_time.text()).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            ts_date = dt.strptime(self.date_time.text(), self.__fmt__).replace(
                tzinfo=timezone.utc
            )
        selected_tz = self.time_zone_offsets.currentText()
        if "UTC - Default" not in selected_tz:
            tz_name = " ".join(selected_tz.split(" ")[1:])
            tz = tzone(tz_name)
            ts_date = ts_date.replace(tzinfo=tz)
        ts_type = TYPE_KEYS.get(ts_format)
        if ts_type is None:
            self._msg_box(
                f"For some reason {ts_format} is not in the list of available conversions!",
                "Error",
            )
            return
        members = type_groups.get(ts_type, (ts_type,))
        if self.encode_radio.isChecked():
            if any(
                single_funcs.get(member, (None, None))[1] is None for member in members
            ):
                msg = (
                    f"Cannot convert to {ts_format}, information required to do this is "
                    "unavailable.\n\n"
                    "This is typically because the timestamp is only a small part of a larger "
                    "value, and the other 'parts' of the value are not available to combine with"
                    " the timestamp to provide a reasonable output."
                )
                self._msg_box(
                    msg,
                    "Warning",
                )
                return
            for member in members:
                result, _ = single_funcs[member][1](ts_date)
                if result:
                    results[member] = result
            if not results:
                self._msg_box(
                    f"Unable to convert {self.date_time.text()} to {ts_format}.",
                    "Warning",
                )
                return
            self.results = results
            self.display_output(results)
        elif self.decode_radio.isChecked():
            ts_text = self.timestamp_text.text()
            if ts_text == "":
                self._msg_box("You must enter a timestamp!", "Info")
                return
            if any(member not in single_funcs for member in members):
                msg = (
                    f"Cannot convert from {ts_format}, information required to do this is "
                    "unavailable.\n\n"
                    "This is typically because the timestamp is only a small part of a larger "
                    "value, and the other 'parts' of are not available within your value to provide"
                    " a reasonable output."
                )
                self._msg_box(
                    msg,
                    "Warning",
                )
                return
            for member in members:
                result, _, _, _, tz_out = single_funcs[member][0](ts_text)
                if not result:
                    continue
                if "UTC - Default" not in selected_tz:
                    result, tz_out, _ = convert_timezone(tz_name, result)
                    if not result:
                        continue
                if tz_out.startswith("+") or tz_out.startswith("-"):
                    results[member] = f"{result}{tz_out}"
                else:
                    results[member] = f"{result} {tz_out}"
            if not results:
                self._msg_box(ts_types[ts_type].reason, "Error")
                return
            self.results = results
            self.display_output(results)

    def csv_decode(self):
        """GUI function to decode contents a CSV/TXT file from selected timestamp format"""
        csv_file_path, _ = QFileDialog.getOpenFileName(
            self, "Select a csv or txt document ...", "", "csv/txt files (*.csv *.txt)"
        )
        self.selected_header = None
        sample_rows = []
        if csv_file_path:
            self.csv_path = os.path.normpath(os.path.abspath(csv_file_path))
            self.csv_content_window = CsvWindow(
                self.timestamp_formats, self.time_zone_offsets, self.dt_format_combo
            )
            style(self.csv_content_window, "csv_window")
            self.csv_content_window.window_label.setFont(self.text_font)
            self.csv_content_window.setWindowTitle("Choose your options for conversion")
            self.csv_content_window.setMaximumWidth(330)
            self.csv_go_button = QPushButton(self.csv_content_window)
            self.csv_go_button.setObjectName("csv_go_button")
            self.csv_go_button.setEnabled(True)
            self.csv_go_button.setHidden(False)
            self.csv_go_button.setFont(self.text_font)
            self.csv_go_button.setText("Go")
            self.csv_go_button.setGeometry(QRect(315, 230, 70, 22))
            style(self.csv_go_button, "csv_window")
            self.csv_go_button.clicked.connect(
                lambda: self.submit_csv_data(
                    csv_file_path,
                    self.csv_content_window.ts_formats.currentText(),
                    self.selected_header,
                    tz_name=self.csv_content_window.time_zones.currentText(),
                    dt_format=date_formats[
                        self.csv_content_window.dt_formats.currentText()
                    ],
                )
            )
            self.select_new_csv = QPushButton(self.csv_content_window)
            self.select_new_csv.setObjectName("select_new_csv")
            self.select_new_csv.setEnabled(True)
            self.select_new_csv.setHidden(False)
            self.select_new_csv.setFont(self.text_font)
            self.select_new_csv.setText("Load new..")
            self.select_new_csv.setGeometry(QRect(240, 260, 70, 22))
            self.select_new_csv.clicked.connect(self.select_new_file)
            self.select_new_csv.setToolTip(
                "Load a new CSV/TXT file to replace the current one."
            )
            self.csv_content_window.ts_formats.setGeometry(QRect(10, 230, 225, 22))
            style(self.csv_content_window.ts_formats, "csv_combo")
            self.csv_content_window.ts_formats.view().setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAsNeeded
            )
            self.csv_content_window.ts_formats.setFont(self.text_font)
            self.csv_content_window.time_zones.setGeometry(QRect(10, 260, 225, 22))
            style(self.csv_content_window.time_zones, "csv_combo")
            self.csv_content_window.time_zones.view().setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAsNeeded
            )
            self.csv_content_window.time_zones.setFont(self.text_font)
            self.csv_content_window.dt_formats.setGeometry(QRect(240, 230, 70, 22))
            self.csv_content_window.dt_formats.setToolTip(
                "Choose your desired date/time format."
            )
            self.csv_content_window.dt_formats.setFont(self.text_font)
            self.csv_close_button = QPushButton(self.csv_content_window)
            self.csv_close_button.setObjectName("csv_close_button")
            self.csv_close_button.setFont(self.text_font)
            self.csv_close_button.setText("Close")
            self.csv_close_button.setGeometry(QRect(315, 260, 70, 22))
            self.csv_close_button.clicked.connect(self.csv_content_window.close)
            try:
                with open(csv_file_path, "r", newline="", encoding="utf-8") as src:
                    sample = src.read(1024)
                    try:
                        dialect = csv.Sniffer().sniff(sample)
                    except csv.Error:
                        dialect = csv.get_dialect("excel")
                    src.seek(0)
                    reader = csv.reader(src, dialect)
                    columns = len(next(reader, None))
                    src.seek(0)
                    rows = 5
                    for row in reader:
                        sample_rows.append(row)
                        rows -= 1
                        if rows == 0:
                            break
            except (FileNotFoundError, PermissionError):
                handle(sys.exc_info())
            self.csv_content_window.output_table.setColumnCount(columns)
            self.csv_content_window.output_table.setRowCount(len(sample_rows))
            self.csv_content_window.output_table.setHorizontalHeaderLabels(
                [str(i + 1) for i in range(columns)]
            )
            self.csv_content_window.output_table.setAlternatingRowColors(True)
            style(self.csv_content_window.output_table, "table")
            self.csv_content_window.output_table.setFont(self.text_font)
            for row_index, row in enumerate(sample_rows):
                for col_index in range(columns):
                    cell_text = row[col_index] if col_index < len(row) else ""
                    item = QTableWidgetItem(cell_text)
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.csv_content_window.output_table.setItem(
                        row_index, col_index, item
                    )
            self.csv_content_window.output_table.verticalHeader().setFixedWidth(1)
            self.csv_content_window.output_table.horizontalHeader().setFixedHeight(1)
            self.csv_content_window.output_table.resizeColumnsToContents()
            self.csv_content_window.output_table.setGeometry(
                QRect(
                    10,
                    50,
                    380,
                    self.csv_content_window.output_table.verticalHeader().length() + 20,
                )
            )
            self.csv_content_window.setFixedSize(
                400,
                290,
            )
            self.csv_content_window.output_table.itemSelectionChanged.connect(
                self.get_column_number
            )
            window_width = self.csv_content_window.width()
            window_height = self.csv_content_window.height()
            self.csv_content_window.window_label.setGeometry(
                QRect(10, 10, window_width - 10, 30)
            )
            self.csv_content_window.window_label.setText(
                (
                    "Select the column which contains your timestamps, then\n "
                    "choose a timestamp format and time zone, then click 'Go'."
                )
            )
            x = (self.screen_layout.width() // 2) - (window_width // 2)
            y = (self.screen_layout.height() // 2) - (window_height // 2)
            self.csv_content_window.move(x, y)
            self.csv_content_window.show()

    def select_new_file(self):
        """Simply closes the open CSV window and reloads to select a new file"""
        self.csv_content_window.close()
        self.csv_decode()

    def submit_csv_data(
        self, csv_file, ts_format, column_num, tz_name=None, dt_format=None
    ):
        """Prepares data to submit for csv conversion"""
        if dt_format is not None and dt_format != self.__fmt__:
            self._set_date_format(dt_format)
        ts_type = TYPE_KEYS.get(ts_format)
        if ts_type is None:
            self._msg_box(
                f"For some reason {ts_format} is not in the list of available conversions!",
                "Error",
            )
            return
        if tz_name is not None and "UTC - Default" not in tz_name:
            tz_name = " ".join(tz_name.split(" ")[1:])
            status, dest, reason = generate_csv(
                csv_file, ts_type, column_num, tz_name=tz_name
            )
        else:
            status, dest, reason = generate_csv(csv_file, ts_type, column_num)
        dest = os.path.normpath(dest)
        if status:
            note = f"\n\n{reason}." if reason else ""
            self._msg_box(f"Output CSV file saved as {dest}.{note}", "Info")
            return
        if reason is None:
            reason = "Unknown"
        self._msg_box(
            f"CSV could not be processed. No output was written.\n\nReason: {reason}",
            "Error",
        )

    def get_column_number(self):
        """Gets the selected column number from the sample data and sets it into a variable"""
        table = self.csv_content_window.output_table
        selected_items = table.selectedItems()
        if selected_items:
            self.selected_header = selected_items[0].column() + 1

    def _menu_bar(self):
        """Add a menu bar"""
        self.menu_bar = self.menuBar()
        style(self.menu_bar, "main")
        self.file_menu = self.menu_bar.addMenu("&File")
        self.exit_action = QAction("&Exit", self)
        self.exit_action.triggered.connect(QApplication.instance().quit)
        self.exit_action.setFont(self.text_font)
        self.csv_decode_action = QAction("&Decode from file ...", self)
        self.csv_decode_action.triggered.connect(self.csv_decode)
        self.csv_decode_action.setFont(self.text_font)
        self.file_menu.addAction(self.csv_decode_action)
        self.file_menu.addAction(self.exit_action)
        self.menu_bar.addMenu(self.file_menu)
        self.view_menu = self.menu_bar.addMenu("&View")
        self.view_action = QAction("E&xamples", self)
        self.view_action.triggered.connect(self._examples)
        self.view_action.setFont(self.text_font)
        self.view_menu.addAction(self.view_action)
        self._theme_menu()
        self.menu_bar.addMenu(self.view_menu)
        self.help_menu = self.menu_bar.addMenu("&Help")
        self.about_action = QAction("&About", self)
        self.about_action.triggered.connect(self._about)
        self.about_action.setFont(self.text_font)
        self.help_menu.addAction(self.about_action)
        self.menu_bar.setFont(self.text_font)

    def _msg_box(self, message, msg_type, buttons="ok"):
        button_choice = None
        if buttons == "ok":
            button_choice = QMessageBox.StandardButton.Ok
        elif buttons == "ok_cancel":
            button_choice = (
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel
            )
        elif buttons == "yes_no_cancel":
            button_choice = (
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel
            )
        elif buttons == "yes_no":
            button_choice = (
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
        self.msg_box = QMessageBox()
        style(self.msg_box, "plain")
        self.msg_box.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        if msg_type == "Error":
            self.msg_box.setIcon(QMessageBox.Icon.Critical)
        elif msg_type == "Info":
            self.msg_box.setIcon(QMessageBox.Icon.Information)
        elif msg_type == "Warning":
            self.msg_box.setIcon(QMessageBox.Icon.Warning)
        elif msg_type == "":
            self.msg_box.setIcon(QMessageBox.Icon.NoIcon)
            msg_type = "Unidentified"
        self.msg_box.setWindowTitle(msg_type)
        self.msg_box.setFixedSize(300, 300)
        self.msg_box.setText(f"{message}\t")
        self.msg_box.setStandardButtons(button_choice)
        x = (self.screen_layout.width() // 2) - (self.msg_box.width() // 2)
        y = (self.screen_layout.height() // 2) - (self.msg_box.height() // 2)
        self.msg_box.move(x, y)
        self.msg_box.exec()

    def _about(self):
        self.about_window = AboutWindow()
        self.about_window.setWindowFlags(
            self.about_window.windowFlags() & ~Qt.WindowType.WindowMinMaxButtonsHint
        )
        github_link = f'<a href="{__source__}">View the source on GitHub</a>'
        self.about_window.setWindowTitle("About")
        self.about_window.about_label.setText(
            f"Version: {__appname__}\nLast Updated: {__date__}\nAuthor: {__author__}"
        )
        self.about_window.about_label.setFont(self.text_font)
        self.about_window.url_label.setOpenExternalLinks(True)
        self.about_window.url_label.setText(github_link)
        self.about_window.url_label.setFont(self.text_font)
        self.logo = QPixmap()
        self.logo.loadFromData(base64.b64decode(self.__fingerprint__))
        self.about_window.logo_label.setPixmap(self.logo)
        self.about_window.logo_label.resize(20, 20)
        about_width = self.about_window.width()
        about_height = self.about_window.height()
        x = (self.screen_layout.width() // 2) - (about_width // 2)
        y = (self.screen_layout.height() // 2) - (about_height // 2)
        self.about_window.move(x, y)
        self.about_window.show()

    def _examples(self):
        if self.examples_window is None:
            structures = {}
            for _, data_list in ts_types.items():
                structures[data_list[0]] = (
                    data_list[1],
                    data_list[2],
                )
            structures = sorted(structures.items(), key=lambda item: item[0].casefold())
            self.examples_window = NewWindow()
            self.examples_window.window_label.setGeometry(QRect(0, 0, 200, 24))
            self.examples_window.setWindowTitle("Timestamp Examples")
            style(self.examples_window, "popup_table")
            self.examples_window.output_table.setColumnCount(2)
            fill_table(
                self.examples_window.output_table,
                [
                    (example[1][0], example[0], example[1][1], False)
                    for example in structures
                ],
            )
            self.examples_window.output_table.horizontalHeader().setFixedHeight(1)
            self.examples_window.output_table.verticalHeader().setFixedWidth(1)
            self.examples_window.output_table.setGeometry(
                QRect(
                    0,
                    0,
                    self.examples_window.output_table.horizontalHeader().length(),
                    self.examples_window.output_table.verticalHeader().length(),
                )
            )
            self.examples_window.output_table.resizeColumnsToContents()
            self.examples_window.output_table.resizeRowsToContents()
            self.examples_window.output_table.setShowGrid(True)
            self.examples_window.output_table.setAlternatingRowColors(True)
            self.examples_window.setFixedSize(
                self.examples_window.output_table.horizontalHeader().length() + 48,
                400,
            )
            self.examples_window.output_table.setFont(self.text_font)
            text = (
                f"{self.examples_window.output_table.rowCount()} timestamp examples. "
                "NOTE: Not all timestamp can be converted TO, as a timestamp may be only PART"
                " of the total value."
            )
            self.examples_window.window_label.setText(text)
            self.examples_window.window_label.setFont(self.text_font)
            x = (self.screen_layout.width() // 2) - (self.examples_window.width() // 2)
            y = (self.screen_layout.height() // 2) - (
                self.examples_window.height() // 2
            )
            self.examples_window.move(x, y)
            self.examples_window.show()
        else:
            self.examples_window.close()
            self.examples_window = None
            self._examples()

    def _new_window(self):
        table_data = self.results
        selected_tz = self.time_zone_offsets.currentText()
        msg = title = ""
        if self.encode_radio.isChecked():
            entered_value = self.date_time.text()
            title = f"Encoded: {entered_value}"
            if "UTC - Default" not in selected_tz:
                entered_value = f"{entered_value} {selected_tz}"
            msg = f"Encoded: {entered_value}"
        elif self.decode_radio.isChecked():
            entered_value = self.timestamp_text.text()
            title = f"Decoded: {entered_value}"
            if "UTC - Default" not in selected_tz:
                entered_value = f"{entered_value} {selected_tz}"
            msg = f"Decoded: {entered_value}"
        if self.new_window is None:
            self.new_window = NewWindow()
            self.new_window.window_label.setGeometry(QRect(0, 0, 200, 24))
            self.new_window.window_label.setText(msg)
            self.new_window.window_label.setFont(self.text_font)
            self.new_window.setWindowTitle(title)
            style(self.new_window, "popup_table")
            self.new_window.output_table.setColumnCount(2)
            fill_table(
                self.new_window.output_table,
                result_rows(table_data, self.decode_radio.isChecked()),
            )
            self.new_window.output_table.horizontalHeader().setFixedHeight(1)
            self.new_window.output_table.verticalHeader().setFixedWidth(1)
            self.new_window.output_table.setGeometry(
                QRect(
                    0,
                    0,
                    self.new_window.output_table.horizontalHeader().length(),
                    self.new_window.output_table.verticalHeader().length(),
                )
            )
            self.new_window.output_table.resizeColumnsToContents()
            for col in range(0, self.new_window.output_table.columnCount()):
                col_width = self.new_window.output_table.columnWidth(col)
                self.new_window.output_table.setColumnWidth(col, col_width + 10)
            self.new_window.output_table.resizeRowsToContents()
            row_height = self.new_window.output_table.rowHeight(
                self.new_window.output_table.rowCount() - 1
            )
            total_row_height = sum(
                row_height for row in range(self.new_window.output_table.rowCount())
            )
            if total_row_height < 400:
                window_height = total_row_height + (row_height * 2) + 8
            else:
                window_height = 400
            self.new_window.output_table.setShowGrid(True)
            self.new_window.output_table.setAlternatingRowColors(True)
            self.new_window.setFixedSize(
                self.new_window.output_table.horizontalHeader().length() + 38,
                window_height,
            )
            self.new_window.output_table.setFont(self.text_font)
            x = (self.screen_layout.width() // 2) - (self.new_window.width() // 2)
            y = (self.screen_layout.height() // 2) - (self.new_window.height() // 2)
            self.new_window.move(x, y)
            self.new_window.show()
        else:
            self.new_window.close()
            self.new_window = None
            self._new_window()


class TimeDecodeGui(QMainWindow, UiMainWindow):
    """TimeDecode Class"""

    stylesheet = main_stylesheet(CLASSIC)
    __fingerprint__ = """
    AAABAAIAMDAAAAEAIACoJQAAJgAAABAQAAABACAAaAQAAM4lAAAoAAAAMAAAAGAAAAABACAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAC9hGcXr4JvPgAAAAAAAAAAwoJYDrZ+V2qwgWEDAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAC/hGd/uIRsVgAAAAC9gmJPqH1n/Zp8bn+hh4UBwYBUH7N6UPCnelWY
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAMWKcAy+h29Juot5BQAAAAC/hGV7s4Bm+6t/aaGpgW4KpX1o
    VpZ4ZfaReGaGAAAAALB7UUCjdk74nHdRcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    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
    """

    def __init__(self):
        """Call and setup the UI"""
        super().__init__()
        self.setup_ui(self)

    def key_press_event(self, event):
        """Create a KeyPress event for a Ctrl+C (Copy) event for selected text"""
        if event.matches(QKeySequence.StandardKey.Copy):
            self.context_menu.copy()
        else:
            super().key_press_event(event)


def run():
    try:
        from ctypes import windll

        app_id = f"digitalsleuth.time-decode.gui.v{__version__.replace('.','-')}"
        windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except ImportError:
        pass
    td_app = QApplication([__appname__, "windows:darkmode=2"])
    td_app.setApplicationDisplayName(__appname__)
    td_app.setApplicationName(__appname__)
    icon = QPixmap()
    icon.loadFromData(base64.b64decode(TimeDecodeGui.__fingerprint__))
    td_app.setWindowIcon(QIcon(icon))
    td_app.setStyle("Fusion")
    restore_scheme()
    td_form = TimeDecodeGui()
    td_form.show()
    td_app.exec()
