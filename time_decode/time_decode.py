#!/usr/bin/env python3
"""
This application is designed to decode timestamps into human-readable date/times and vice-versa
Additional information regarding the source of the timestamp formats and associated equations
is provided in the REFERENCES.md file at https://github.com/digitalsleuth/time_decode.
"""

from datetime import datetime as dt, timedelta, timezone
import struct
from string import hexdigits
import argparse
import inspect
import math
import re
import sys
import os
import base64
import uuid
import traceback
import warnings
from calendar import monthrange, IllegalMonthError
from typing import NamedTuple
from zoneinfo import ZoneInfo as tzone
import tzdata
import juliandate as jd
from colorama import init
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import DecoderException
from ulid import ULID
from prettytable import PrettyTable, TableStyle
from PyQt6.QtCore import (
    QRect,
    Qt,
    QMetaObject,
    QCoreApplication,
    QDate,
    QSize,
)
from PyQt6.QtGui import (
    QAction,
    QPixmap,
    QIcon,
    QFont,
    QKeySequence,
    QColor,
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
)

warnings.filterwarnings("ignore", category=DeprecationWarning)
init(autoreset=True)

__author__ = "Corey Forman (digitalsleuth)"
__date__ = "2025-05-11"
__version__ = "10.0.0"
__description__ = "Python 3 Date Time Conversion Tool"
__fmt__ = "%Y-%m-%d %H:%M:%S.%f"
__red__ = "\033[1;31m"
__clr__ = "\033[1;m"
__source__ = "https://github.com/digitalsleuth/time_decode"
__appname__ = f"Time Decode v{__version__}"


try:
    from ctypes import windll

    APP_ID = f"digitalsleuth.time-decode.gui.v{__version__.replace('.','-')}"
    windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
except ImportError:
    pass


class NewWindow(QWidget):
    """This class sets the structure for a new window"""

    def __init__(self):
        """Sets up the new window table and context menu"""
        super().__init__()
        layout = QVBoxLayout()
        self.window_label = QLabel()
        self.timestamp_table = QTableWidget()
        self.timestamp_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.timestamp_table.setStyleSheet(
            "border: none; selection-background-color: #1644b9;"
        )
        self.timestamp_table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.context_menu = ContextMenu(self.timestamp_table)
        self.timestamp_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.timestamp_table.customContextMenuRequested.connect(
            self.context_menu.show_context_menu
        )
        layout.addWidget(self.timestamp_table)
        layout.addWidget(self.window_label)
        self.setLayout(layout)

    def key_press_event(self, event):
        """Sets the Ctrl+C KeyPress for the window"""
        if event.matches(QKeySequence.StandardKey.Copy):
            self.context_menu.copy()
        else:
            super().key_press_event(event)


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
        self.setStyleSheet("background-color: white; color: black;")
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
            text = (
                "\n".join(
                    [
                        "\t".join(
                            [
                                item.text()
                                for item in self.tbl_widget.selectedItems()
                                if item.row() == row
                            ]
                        )
                        for row in range(self.tbl_widget.rowCount())
                    ]
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
        self.timestamp_text = None
        self.date_time = None
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
        self.help_menu = None
        self.about_action = None
        self.msg_box = None
        self.about_window = None
        self.logo = None
        self.timestamp_count_label = None
        self.screen_layout = QApplication.primaryScreen().availableGeometry()
        self.center_x = (self.screen_layout.width() // 2) - (self.window_width // 2)
        self.center_y = (self.screen_layout.height() // 2) - (self.window_height // 2)

    def setup_ui(self, main_window):
        """Sets up the core UI"""
        if not main_window.objectName():
            main_window.setObjectName(__appname__)
        main_window.setFixedWidth(self.window_width)
        main_window.setMinimumHeight(self.window_height)
        main_window.setStyleSheet(main_window.stylesheet)
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
        self.timestamp_text.setStyleSheet(main_window.stylesheet)
        self.timestamp_text.setFont(self.text_font)
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
        self.date_time.setStyleSheet(main_window.stylesheet)
        self.date_time.calendarWidget().setStyleSheet(
            "alternate-background-color: #EAF6FF; background-color: white; color: black;"
        )
        self.date_time.setFont(self.text_font)
        self.date_time.calendarWidget().setFont(self.text_font)
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
        self.timestamp_formats.setStyleSheet(
            "combobox-popup: 0; background-color: white; color: black;"
        )
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
        self.time_zone_offsets.setStyleSheet(
            "combobox-popup: 0; background-color: white; color: black;"
        )
        self.time_zone_offsets.view().setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.time_zone_offsets.setFont(self.text_font)
        ts_offsets = self.common_timezone_offsets()
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
        self.output_table.setStyleSheet(
            "border: none; background-color: white; color: black; font-size: 10;"
        )
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
        self.guess_button.setStyleSheet("background-color: white; color: black;")
        self.guess_button.setFont(self.text_font)
        self.guess_button.clicked.connect(self.guess_decode)
        self.to_all_button = QPushButton(main_window)
        self.to_all_button.setObjectName("to_all_button")
        self.to_all_button.setEnabled(False)
        self.to_all_button.setHidden(True)
        self.to_all_button.setGeometry(QRect(245, 30, 70, 22))
        self.to_all_button.setStyleSheet("background-color: white; color: black;")
        self.to_all_button.setFont(self.text_font)
        self.to_all_button.clicked.connect(self.encode_toall)
        self.encode_radio = QRadioButton(main_window)
        self.encode_radio.setObjectName("encode_radio")
        self.encode_radio.setGeometry(QRect(400, 30, 72, 20))
        self.encode_radio.setStyleSheet("background-color: white; color: black;")
        self.encode_radio.setFont(self.text_font)
        self.encode_radio.toggled.connect(self._encode_select)
        self.decode_radio = QRadioButton(main_window)
        self.decode_radio.setObjectName("decode_radio")
        self.decode_radio.setGeometry(QRect(325, 30, 72, 20))
        self.decode_radio.setChecked(True)
        self.decode_radio.setStyleSheet("background-color: white; color: black;")
        self.decode_radio.setFont(self.text_font)
        self.decode_radio.toggled.connect(self._decode_select)
        self.go_button = QPushButton(main_window)
        self.go_button.setObjectName("go_button")
        self.go_button.setGeometry(QRect(245, 60, 70, 22))
        self.go_button.setStyleSheet("background-color: white; color: black;")
        self.go_button.setFont(self.text_font)
        self.go_button.clicked.connect(self.go_function)
        new_window_pixmap = QStyle.StandardPixmap.SP_ArrowUp
        icon = main_window.style().standardIcon(new_window_pixmap)
        self.new_window_button = QPushButton(main_window)
        self.new_window_button.setObjectName("new_window_button")
        self.new_window_button.setGeometry(QRect(325, 90, 22, 22))
        self.new_window_button.setStyleSheet(
            "background-color: white; color: black; border: 0;"
        )
        self.new_window_button.setFont(self.text_font)
        self.new_window_button.setIcon(icon)
        self.new_window_button.setIconSize(QSize(22, 22))
        self.new_window_button.setToolTip("Open results in a new window")
        self.new_window_button.clicked.connect(self._new_window)
        if os.sys.platform == "linux":
            vert = 415
        else:
            vert = 370
        self.timestamp_count_label = QLabel(main_window)
        self.timestamp_count_label.setGeometry(QRect(vert, 94, 90, 22))
        self.timestamp_count_label.setStyleSheet(
            "background-color: white; color: black;"
        )
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
        self.go_button.setText(_translate("main_window", "\u2190 From", None))
        self.new_window_button.setHidden(True)
        self.new_window_button.setEnabled(False)
        self._menu_bar()

    def set_now(self):
        """Sets the current date / time on the Calendar Widget"""
        today = QDate().currentDate()
        now = dt.now(timezone.utc)
        self.date_time.calendarWidget().setSelectedDate(today)
        self.date_time.setDateTime(now)

    def update_timezones(self):
        """Updates the time_zone_offsets combo box to reflect the selected Calendar date/time"""
        ts_offsets = self.common_timezone_offsets()
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
        self.go_button.setText("\u2190 From")
        self.new_window_button.setHidden(True)
        self.new_window_button.setEnabled(False)
        self.timestamp_count_label.setText("")
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
        self.go_button.setText("\u2190 To")
        self.new_window_button.setHidden(True)
        self.new_window_button.setEnabled(False)
        self.timestamp_count_label.setText("")
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
        self.output_table.setStyleSheet("border: none")

    def guess_decode(self):
        """Will take the provided timestamp and run it through the 'from_all' function"""
        timestamp = self.timestamp_text.text()
        selected_tz = self.time_zone_offsets.currentText()
        if timestamp == "":
            self._msg_box("You must enter a timestamp!", "Info")
            return
        all_ts = from_all(timestamp)
        results = {}
        for k, _ in all_ts.items():
            if "UTC - Default" in selected_tz:
                results[k] = f"{all_ts[k][0]} {all_ts[k][2]}"
            else:

                tz_name = " ".join(selected_tz.split(" ")[1:])
                tz = tzone(tz_name)
                tz_original = all_ts[k][0]
                dt_obj = dt.fromisoformat(tz_original).replace(tzinfo=timezone.utc)
                tz_change = dt_obj.astimezone(tz)
                tz_selected = tz_change.strftime(__fmt__)
                tz_offset = tz_change.strftime("%z")
                tz_offset = f"{tz_offset[:3]}:{tz_offset[3:]}"
                if self.check_daylight(dt_obj, tz):
                    tz_out = f"{tz_offset} DST"
                else:
                    tz_out = tz_offset
                results[k] = f"{tz_selected} {tz_out}"
        self.results = results
        self.display_output(results)

    def encode_toall(self):
        """Takes the date_time object, passes it to the to_timestamps function which encodes it"""
        dt_val = self.date_time.text()
        dt_obj = dt.fromisoformat(dt_val)
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

    def tzdata_timezones(self):
        """Get the tzdata timezones and put them in a list for the timezone drop-down"""
        zoneinfo_dir = os.path.join(tzdata.__path__[0], "zoneinfo")
        timezones = set()
        for root, _, files in os.walk(zoneinfo_dir):
            for name in files:
                rel_path = os.path.relpath(os.path.join(root, name), zoneinfo_dir)
                if rel_path.startswith(("posix", "right")):
                    continue
                timezones.add(rel_path)
        return sorted(timezones)

    def common_timezone_offsets(self):
        """Generates a list of all tzdata timezones for conversion, sorted by UTC offset"""
        timezone_offsets = [("UTC - Default", "")]
        dt_obj = dt.fromisoformat(self.date_time.text()).replace(tzinfo=timezone.utc)
        duplicates = [
            "Factory",
            "Zulu",
            "Etc\\Zulu",
            "Etc\\UTC",
            "GMT-0",
            "GMT+0",
            "Etc\\Universal",
            "GMT0",
            "UCT",
            "Etc\\Greenwich",
            "Etc\\GMT",
            "Etc\\GMT+0",
            "Etc\\GMT-0",
            "Etc\\GMT0",
            "Etc\\UCT",
            "Universal",
        ]
        for tz_name in self.tzdata_timezones():
            if tz_name in duplicates:
                continue
            try:
                set_timezone = tzone(tz_name)
                dt_val = dt_obj.astimezone(set_timezone)
                offset_tz = dt_val.utcoffset()
                if offset_tz is None:
                    continue
                offset_seconds = offset_tz.total_seconds()
                hours, remainder = divmod(abs(offset_seconds), 3600)
                minutes = remainder // 60
                sign = "+" if offset_seconds >= 0 else "-"
                int_offset = f"{sign}{int(hours):02}:{int(minutes):02}"
                formatted_offset = f"UTC{int_offset}"
                timezone_offsets.append((formatted_offset, tz_name))
            except Exception:
                continue
        timezone_offsets.sort(key=lambda x: x[0])
        return timezone_offsets

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
        elif os.sys.platform in {"win32", "darwin"}:
            tbl_fixed_width = 475
            col2_width = 235
            self_fixed_width = 490
        self.output_table.setVisible(True)
        self.output_table.setColumnCount(2)
        self.output_table.setAlternatingRowColors(True)
        self.output_table.setStyleSheet(
            """
            border: none;
            alternate-background-color: #EAF6FF;
            background-color: white;
            color: black;
            selection-background-color: #1644b9;
            """
        )
        for ts_type, result in ts_list.items():
            row = self.output_table.rowCount()
            self.output_table.insertRow(row)
            widget0 = QTableWidgetItem(ts_types[ts_type][0])
            widget0.setFlags(widget0.flags() & ~Qt.ItemFlag.ItemIsEditable)
            widget0.setToolTip(ts_types[ts_type][1])
            widget1 = QTableWidgetItem(result)
            widget1.setFlags(widget1.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.output_table.setItem(row, 0, widget0)
            self.output_table.item(row, 0).setTextAlignment(
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            )
            self.output_table.setItem(row, 1, widget1)
            self.output_table.item(row, 1).setTextAlignment(
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            )
            if self.decode_radio.isChecked():
                ts = " ".join(result.split(" ")[:-1])
                this_yr = int(dt.now(timezone.utc).strftime("%Y"))
                if int(dt.fromisoformat(ts).strftime("%Y")) in range(
                    this_yr - 5, this_yr + 5
                ):
                    for each_col in range(0, self.output_table.columnCount()):
                        this_col = self.output_table.item(row, each_col)
                        this_col.setBackground(QColor("lightgreen"))
                        this_col.setForeground(QColor("black"))
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
            self.setFixedHeight(self.height() + int(total_row_height + 1))
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
        ts_format = self.timestamp_formats.currentText()
        ts_text = self.timestamp_text.text()
        ts_date = dt.fromisoformat(self.date_time.text()).replace(tzinfo=timezone.utc)
        selected_tz = self.time_zone_offsets.currentText()
        if "UTC - Default" not in selected_tz:
            tz_name = " ".join(selected_tz.split(" ")[1:])
            tz = tzone(tz_name)
            ts_date = ts_date.astimezone(tz)
        in_ts_types = [k for k, v in ts_types.items() if ts_format in v]
        if not in_ts_types:
            self._msg_box(
                f"For some reason {ts_format} is not in the list of available conversions!",
                "Error",
            )
            return
        ts_type = in_ts_types[0]
        if self.encode_radio.isChecked():
            is_func = False
            ts_selection = f"to_{ts_type}"
            for _, funcs in single_funcs.items():
                this_func = funcs[1]
                if inspect.isfunction(this_func):
                    func_name = this_func.__name__
                    if func_name == ts_selection:
                        is_func = True
            if not is_func:
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
            ts_func = globals()[ts_selection]
            result, _ = ts_func(ts_date)
            results[ts_type] = result
            self.results = results
            self.display_output(results)
        elif self.decode_radio.isChecked():
            is_func = False
            if ts_text == "":
                self._msg_box("You must enter a timestamp!", "Info")
                return
            ts_selection = f"from_{ts_type}"
            for _, funcs in single_funcs.items():
                this_func = funcs[0]
                if inspect.isfunction(this_func):
                    func_name = this_func.__name__
                    if func_name == ts_selection:
                        is_func = True
            if not is_func:
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
            ts_func = globals()[ts_selection]
            result, _, _, reason, tz_out = ts_func(ts_text)
            if not result:
                self._msg_box(reason, "Error")
                return
            if "UTC - Default" not in selected_tz:
                dt_obj = dt.fromisoformat(result).replace(tzinfo=timezone.utc)
                tz_change = dt_obj.astimezone(tz)
                tz_offset = tz_change.strftime("%z")
                tz_offset = f"{tz_offset[:3]}:{tz_offset[3:]}"
                result = tz_change.strftime(__fmt__)
                if self.check_daylight(dt_obj, tz):
                    tz_out = f"{tz_offset} DST"
                else:
                    tz_out = tz_offset
            results[ts_type] = f"{result} {tz_out}"
            self.results = results
            self.display_output(results)

    @staticmethod
    def check_daylight(dtval, tz):
        """Checks to see if the provided timestamp, in the provided timezone, is observing DST"""
        if dtval.tzinfo is None:
            dtval = dtval.replace(tzinfo=tz)
        else:
            dtval = dtval.astimezone(tz)
        return dtval.dst() != timedelta(0, 0)

    def _menu_bar(self):
        """Add a menu bar"""
        self.menu_bar = self.menuBar()
        self.menu_bar.setStyleSheet(self.stylesheet)
        self.file_menu = self.menu_bar.addMenu("&File")
        self.exit_action = QAction("&Exit", self)
        self.exit_action.triggered.connect(QApplication.instance().quit)
        self.exit_action.setFont(self.text_font)
        self.file_menu.addAction(self.exit_action)
        self.menu_bar.addMenu(self.file_menu)
        self.view_menu = self.menu_bar.addMenu("&View")
        self.view_action = QAction("E&xamples", self)
        self.view_action.triggered.connect(self._examples)
        self.view_action.setFont(self.text_font)
        self.view_menu.addAction(self.view_action)
        self.menu_bar.addMenu(self.view_menu)
        self.help_menu = self.menu_bar.addMenu("&Help")
        self.about_action = QAction("&About", self)
        self.about_action.triggered.connect(self._about)
        self.about_action.setFont(self.text_font)
        self.help_menu.addAction(self.about_action)
        self.menu_bar.setFont(self.text_font)

    def _msg_box(self, message, msg_type):
        self.msg_box = QMessageBox()
        self.msg_box.setStyleSheet("background-color: white; color: black;")
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
        self.msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
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
            structures = sorted(
                structures.items(), key=lambda item: item[1][0].casefold()
            )
            self.examples_window = NewWindow()
            self.examples_window.window_label.setGeometry(QRect(0, 0, 200, 24))
            self.examples_window.setWindowTitle("Timestamp Examples")
            self.examples_window.setStyleSheet(
                """
                border: none; alternate-background-color: #EAF6FF;
                background-color: white; color: black;
                """
            )
            self.examples_window.timestamp_table.setColumnCount(2)
            for example in structures:
                row = self.examples_window.timestamp_table.rowCount()
                self.examples_window.timestamp_table.insertRow(row)
                widget0 = QTableWidgetItem(example[1][0])
                widget0.setFlags(widget0.flags() & ~Qt.ItemFlag.ItemIsEditable)
                widget0.setToolTip(example[0])
                widget1 = QTableWidgetItem(example[1][1])
                widget1.setFlags(widget1.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.examples_window.timestamp_table.setItem(row, 0, widget0)
                self.examples_window.timestamp_table.item(row, 0).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
                self.examples_window.timestamp_table.item(row, 0)
                self.examples_window.timestamp_table.setItem(row, 1, widget1)
                self.examples_window.timestamp_table.item(row, 1).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
            self.examples_window.timestamp_table.horizontalHeader().setFixedHeight(1)
            self.examples_window.timestamp_table.verticalHeader().setFixedWidth(1)
            self.examples_window.timestamp_table.setGeometry(
                QRect(
                    0,
                    0,
                    self.examples_window.timestamp_table.horizontalHeader().length(),
                    self.examples_window.timestamp_table.verticalHeader().length(),
                )
            )
            self.examples_window.timestamp_table.resizeColumnsToContents()
            self.examples_window.timestamp_table.resizeRowsToContents()
            self.examples_window.timestamp_table.setShowGrid(True)
            self.examples_window.timestamp_table.setAlternatingRowColors(True)
            self.examples_window.setFixedSize(
                self.examples_window.timestamp_table.horizontalHeader().length() + 48,
                400,
            )
            self.examples_window.timestamp_table.setFont(self.text_font)
            text = (
                f"{self.examples_window.timestamp_table.rowCount()} timestamp examples. "
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
            self.new_window.setStyleSheet(
                """
                border: none; alternate-background-color: #EAF6FF;
                background-color: white; color: black;
                """
            )
            self.new_window.timestamp_table.setColumnCount(2)
            for ts_type, result in table_data.items():
                row = self.new_window.timestamp_table.rowCount()
                self.new_window.timestamp_table.insertRow(row)
                widget0 = QTableWidgetItem(ts_types[ts_type][0])
                widget0.setFlags(widget0.flags() & ~Qt.ItemFlag.ItemIsEditable)
                widget0.setToolTip(ts_types[ts_type][1])
                widget1 = QTableWidgetItem(result)
                widget1.setFlags(widget1.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.new_window.timestamp_table.setItem(row, 0, widget0)
                self.new_window.timestamp_table.item(row, 0).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
                self.new_window.timestamp_table.item(row, 0)
                self.new_window.timestamp_table.setItem(row, 1, widget1)
                self.new_window.timestamp_table.item(row, 1).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
                if self.decode_radio.isChecked():
                    ts = " ".join(result.split(" ")[:-1])
                    this_yr = int(dt.now(timezone.utc).strftime("%Y"))
                    if int(dt.fromisoformat(ts).strftime("%Y")) in range(
                        this_yr - 5, this_yr + 5
                    ):
                        for each_col in range(
                            0, self.new_window.timestamp_table.columnCount()
                        ):
                            this_col = self.new_window.timestamp_table.item(
                                row, each_col
                            )
                            this_col.setBackground(QColor("lightgreen"))
                            this_col.setForeground(QColor("black"))
            self.new_window.timestamp_table.horizontalHeader().setFixedHeight(1)
            self.new_window.timestamp_table.verticalHeader().setFixedWidth(1)
            self.new_window.timestamp_table.setGeometry(
                QRect(
                    0,
                    0,
                    self.new_window.timestamp_table.horizontalHeader().length(),
                    self.new_window.timestamp_table.verticalHeader().length(),
                )
            )
            self.new_window.timestamp_table.resizeColumnsToContents()
            for col in range(0, self.new_window.timestamp_table.columnCount()):
                col_width = self.new_window.timestamp_table.columnWidth(col)
                self.new_window.timestamp_table.setColumnWidth(col, col_width + 10)
            self.new_window.timestamp_table.resizeRowsToContents()
            row_height = self.new_window.timestamp_table.rowHeight(row)
            total_row_height = sum(
                row_height for row in range(self.new_window.timestamp_table.rowCount())
            )
            if total_row_height < 400:
                window_height = total_row_height + (row_height * 2) + 8
            else:
                window_height = 400
            self.new_window.timestamp_table.setShowGrid(True)
            self.new_window.timestamp_table.setAlternatingRowColors(True)
            self.new_window.setFixedSize(
                self.new_window.timestamp_table.horizontalHeader().length() + 38,
                window_height,
            )
            self.new_window.timestamp_table.setFont(self.text_font)
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

    stylesheet = """
        QMainWindow {
            background-color: white; color: black;
        }
        QLineEdit {
            background-color: white; color: black;
        }
        QDateTimeEdit {
            background-color: white; color: black;
        }
        QMenu {
            background-color: white; color: black; border: 1px solid black; margin: 0;
        }
        QMenu::item {
            background-color: white; color: black; margin: 0; padding: 4px 20px 4px 20px;
        }
        QMenu::item:selected {
            background-color: #1644b9; color: white; margin: 0; padding: 4px 20px 4px 20px;
        }
        QMenuBar {
            background-color: white; color: black;
        }
        QMenuBar::item {
            background-color: white; color: black;
        }
        QMenuBar::item:selected {
            background-color: #1644b9; color: white;
        }
        """
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


class TsTypes(NamedTuple):
    """Defines the structure of a Timestamp Type"""

    ts_type: str
    reason: str
    example: str
    time_zone: str


ts_types = {
    "active": TsTypes(
        "Active Directory/LDAP",
        "Active Directory/LDAP timestamps are 18 digits",
        "133908455300649390",
        "UTC",
    ),
    "apache": TsTypes(
        "Apache Cookie Hex time",
        "Apache Cookie hex timestamps are 13 hex characters long",
        "63450e689882b",
        "UTC",
    ),
    "biome64": TsTypes(
        "Apple Biome 64-bit decimal",
        "Apple Biome 64-bit decimal is 19 digits in length",
        "4739726202305531884",
        "UTC",
    ),
    "biomehex": TsTypes(
        "Apple Biome hex time",
        "Apple Biome Hex value is 8 bytes (16 chars) long",
        "41c6e3de6d084fec",
        "UTC",
    ),
    "mac": TsTypes(
        "Apple NSDate - Mac Absolute",
        "Apple NSDates (Mac) are 9 digits '.' 6 digits",
        "768064730.064939",
        "UTC",
    ),
    "iostime": TsTypes(
        "Apple NSDate - iOS 11+",
        "Apple NSDates (iOS) are 15-19 digits in length",
        "768064730064939008",
        "UTC",
    ),
    "bplist": TsTypes(
        "Apple NSDate - bplist / Cocoa",
        "Apple NSDates (bplist) are 9 digits in length",
        "768064730",
        "UTC",
    ),
    "nsdate": TsTypes(
        "Apple NSDate - All",
        "Apple NSDates are 9, 9.6, or 15-19 digits in length",
        "704656778.285777",
        "UTC",
    ),
    "bcd": TsTypes(
        "Binary Coded Decimal",
        "Binary Coded Decimal timestamps are 12 digits in length",
        "250506232221",
        "Local",
    ),
    "bitdate": TsTypes(
        "BitDate time",
        "BitDate (Samsung/LG) timestamps are 8 hex characters",
        "d223957e",
        "Local",
    ),
    "bitdec": TsTypes(
        "Bitwise Decimal time",
        "Bitwise Decimal timestamps are 10 digits",
        "2123703250",
        "Local",
    ),
    "dhcp6": TsTypes(
        "DHCPv6 DUID time",
        "DHCPv6 DUID values are at least 14 bytes long",
        "000100012faa41da000000000000",
        "UTC",
    ),
    "discord": TsTypes(
        "Discord time",
        "Discord timestamps are 18 digits or longer",
        "1102608904745127937",
        "UTC",
    ),
    "dvr": TsTypes(
        "DVR (WFS / DHFS) File System",
        "DVR timestamps are 4 bytes",
        "00F0063F",
        "Local",
    ),
    "exfat": TsTypes(
        "exFAT time",
        "exFAT 32-bit timestamps are 8 hex characters (4 bytes)",
        "5aa47a59",
        "Local",
    ),
    "fat": TsTypes(
        "FAT Date + Time",
        "FAT (MS-DOS wFatDate wFatTime) timestamps are 8 hex characters (4 bytes)",
        "a45a597a",
        "Local",
    ),
    "gbound": TsTypes(
        "GMail Boundary time",
        "GMail Boundary values are 28 hex chars",
        "00000000000089882b063450e600",
        "UTC",
    ),
    "gmsgid": TsTypes(
        "GMail Message ID time",
        "GMail Message ID values are 16 hex chars or 19 digits (IMAP)",
        "1969be0e7d000000",
        "UTC",
    ),
    "chrome": TsTypes(
        "Google Chrome",
        "Google Chrome/Webkit timestamp is 17 digits",
        "13390845530064940",
        "UTC",
    ),
    "eitime": TsTypes(
        "Google EI time",
        "Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "WoUXaA",
        "UTC",
    ),
    "gclid": TsTypes(
        "Google GCLID time",
        "Google GCLID timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "CKSDxc_qhLkCFQyk4AodO24Arg",
        "UTC",
    ),
    "ved": TsTypes(
        "Google VED time",
        "Google VED timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "0ahUKEwilufv7joqNAxW3nYkEHd0vMyIQ4dUDCA8",
        "UTC",
    ),
    "gps": TsTypes("GPS time", "GPS timestamps are 10 digits", "1430407111", "UTC"),
    "gsm": TsTypes(
        "GSM time",
        "GSM timestamps are 14 hex characters (7 bytes)",
        "52504051810500",
        "UTC",
    ),
    "hfsbe": TsTypes(
        "HFS/HFS+ 32-bit Hex BE",
        "HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)",
        "e43d35da",
        "HFS Local / HFS+ UTC",
    ),
    "hfsle": TsTypes(
        "HFS/HFS+ 32-bit Hex LE",
        "HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)",
        "da353de4",
        "HFS Local / HFS+ UTC",
    ),
    "hfsdec": TsTypes(
        "HFS+ Decimal Time",
        "HFS+ Decimal timestamps are 10 digits",
        "3829216730",
        "UTC",
    ),
    "juliandec": TsTypes(
        "Julian Date decimal",
        "Julian Date decimal values are 7 digits, a decimal, and up to 10 digits",
        "2460800.1380787035",
        "UTC",
    ),
    "julianhex": TsTypes(
        "Julian Date hex",
        "Julian Date hex values are 14 characters (7 bytes)",
        "258c80524d235b",
        "UTC",
    ),
    "ksalnum": TsTypes(
        "KSUID Alpha-numeric",
        "KSUID values are 27 alpha-numeric characters",
        "2PChRqPZDwT9m2gBDLd5uy7XNTr",
        "UTC",
    ),
    "ksdec": TsTypes(
        "KSUID Decimal",
        "KSUID decimal timestamps are 9 digits in length",
        "346371930",
        "UTC",
    ),
    "leb128hex": TsTypes(
        "LEB128 Hex time",
        "LEB128 Hex timestamps are variable-length and even-length",
        "d0cf83dfe932",
        "UTC",
    ),
    "linkedin": TsTypes(
        "LinkedIn Activity time",
        "LinkedIn Activity timestamps contain only digits",
        "7324176984442343424",
        "UTC",
    ),
    "mastodon": TsTypes(
        "Mastodon time",
        "Mastodon timestamps are 18 digits or longer",
        "114450230804480000",
        "UTC",
    ),
    "metasploit": TsTypes(
        "Metasploit Payload UUID",
        "Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded",
        "4PGoVGYmx8l6F3sVI4Rc8g",
        "UTC",
    ),
    "dotnet": TsTypes(
        "Microsoft .NET DateTime Ticks",
        "Microsoft .NET DateTime Ticks values are 18 digits",
        "638819687300649472",
        "UTC",
    ),
    "systemtime": TsTypes(
        "Microsoft 128-bit SYSTEMTIME",
        "Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)",
        "e9070500000004000f00120032004000",
        "UTC",
    ),
    "dttm": TsTypes(
        "Microsoft DTTM Date",
        "Microsoft DTTM timestamps are 4 bytes",
        "8768f513",
        "Local",
    ),
    "ms1904": TsTypes(
        "Microsoft Excel 1904 Date",
        "Microsoft Excel 1904 timestamps are 2 ints, separated by a dot",
        "44319.638079455312",
        "UTC",
    ),
    "hotmail": TsTypes(
        "Microsoft Hotmail time",
        "Microsoft Hotmail timestamps are 2x 8 hex chars (4 bytes) colon separated",
        "07bddb01:aed19dd6",
        "UTC",
    ),
    "msdos": TsTypes(
        "Microsoft MS-DOS 32-bit Hex",
        "Microsoft MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)",
        "597aa45a",
        "Local",
    ),
    "moto": TsTypes(
        "Motorola time",
        "Motorola 6-byte hex timestamps are 12 hex characters",
        "3705040f1232",
        "UTC",
    ),
    "prtime": TsTypes(
        "Mozilla PRTime",
        "Mozilla PRTime timestamps are 16 digits",
        "1746371930064939",
        "UTC",
    ),
    "nokia": TsTypes(
        "Nokia time",
        "Nokia 4-byte hex timestamps are 8 hex characters",
        "d19d0f5a",
        "UTC",
    ),
    "nokiale": TsTypes(
        "Nokia time LE",
        "Nokia 4-byte hex timestamps are 8 hex characters",
        "5a0f9dd1",
        "UTC",
    ),
    "ns40": TsTypes(
        "Nokia S40 time",
        "Nokia 7-byte hex timestamps are 14 hex characters",
        "07e905040f1232",
        "UTC",
    ),
    "ns40le": TsTypes(
        "Nokia S40 time LE",
        "Nokia 7-byte hex timestamps are 14 hex characters",
        "e90705040f1232",
        "UTC",
    ),
    "s32": TsTypes(
        "S32 Encoded (Bluesky) time",
        "S32 encoded (Bluesky) timestamps are 9 characters long",
        "3muhy3twk",
        "UTC",
    ),
    "semioctet": TsTypes(
        "Semi-Octet decimal",
        "Semi-Octet decimal values are 12 or 14 digits long",
        "525040518105",
        "Local",
    ),
    "sony": TsTypes(
        "Sonyflake time",
        "Sonyflake values are 15 hex characters",
        "65dd4bb89000001",
        "UTC",
    ),
    "symantec": TsTypes(
        "Symantec AV time",
        "Symantec 6-byte hex timestamps are 12 hex characters",
        "3704040f1232",
        "UTC",
    ),
    "tiktok": TsTypes(
        "TikTok time",
        "TikTok timestamps are 19 digits long",
        "7228142017547750661",
        "UTC",
    ),
    "twitter": TsTypes(
        "Twitter time",
        "Twitter timestamps are 18 digits or longer",
        "1189581422684274688",
        "UTC",
    ),
    "ulid": TsTypes(
        "ULID time",
        "ULID timestamp contains only Base32 characters",
        "01JTDY1SYGCZWCBPCSEBHV1DW2",
        "UTC",
    ),
    "unixhex32be": TsTypes(
        "Unix Hex 32-bit BE",
        "Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)",
        "6817855a",
        "UTC",
    ),
    "unixhex32le": TsTypes(
        "Unix Hex 32-bit LE",
        "Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)",
        "5a851768",
        "UTC",
    ),
    "unixmilli": TsTypes(
        "Unix Milliseconds",
        "Unix milliseconds timestamp is 13 digits in length",
        "1746371930064",
        "UTC",
    ),
    "unixmillihex": TsTypes(
        "Unix Milliseconds hex",
        "Unix Milliseconds hex timestamp is 12 hex characters (6 bytes)",
        "01969be0e7d0",
        "UTC",
    ),
    "unixsec": TsTypes(
        "Unix Seconds",
        "Unix seconds timestamp is 10 digits in length",
        "1746371930",
        "UTC",
    ),
    "uuid": TsTypes(
        "UUID time",
        "UUIDs are in the format 00000000-0000-0000-0000-000000000000",
        "d93026f0-e857-11ed-a05b-0242ac120003",
        "UTC",
    ),
    "vm": TsTypes(
        "VMSD time",
        "VMSD values are a 6-digit value and a signed/unsigned int at least 9 digits",
        "406608,-427259264",
        "UTC",
    ),
    "cookie": TsTypes(
        "Windows Cookie Date",
        "Windows Cookie times consist of 2 ints, entered with a comma between them",
        "3600017664,31177991",
        "UTC",
    ),
    "filetimebe": TsTypes(
        "Windows FILETIME BE",
        "Windows FILETIME Hex Big-Endian timestamp is 16 hex characters (8 bytes)",
        "01dbbd07d69dd1ae",
        "UTC",
    ),
    "filetimele": TsTypes(
        "Windows FILETIME LE",
        "Windows FILETIME Hex Little-Endian timestamp is 16 hex characters (8 bytes)",
        "aed19dd607bddb01",
        "UTC",
    ),
    "filetimelohi": TsTypes(
        "Windows FILETIME (Low:High)",
        "Windows FILETIME Low:High times are 2x 8 hex chars (4 bytes) colon separated",
        "d69dd1ae:01dbbd07",
        "UTC",
    ),
    "olebe": TsTypes(
        "Windows OLE 64-bit hex BE",
        "Windows OLE Big-Endian timestamps are 16 hex characters (8 bytes)",
        "40e65ab46b259b1a",
        "UTC",
    ),
    "olele": TsTypes(
        "Windows OLE 64-bit hex LE",
        "Windows OLE Little-Endian timestamps are 16 hex characters (8 bytes)",
        "1a9b256bb45ae640",
        "UTC",
    ),
    "oleauto": TsTypes(
        "Windows OLE Automation Date",
        "Windows OLE Automation timestamps are 2 ints, separated by a dot",
        "45781.638079455312",
        "UTC",
    ),
}
__types__ = len(ts_types)

epochs = {
    1: dt(1, 1, 1, tzinfo=timezone.utc),
    1582: dt(1582, 10, 15, tzinfo=timezone.utc),
    1601: dt(1601, 1, 1, tzinfo=timezone.utc),
    1899: dt(1899, 12, 30, tzinfo=timezone.utc),
    1904: dt(1904, 1, 1, tzinfo=timezone.utc),
    1970: dt(1970, 1, 1, tzinfo=timezone.utc),
    1980: dt(1980, 1, 6, tzinfo=timezone.utc),
    2000: dt(2000, 1, 1, tzinfo=timezone.utc),
    2001: dt(2001, 1, 1, tzinfo=timezone.utc),
    2050: dt(2050, 1, 1, tzinfo=timezone.utc),
    "hundreds_nano": 10000000,
    "nano_2001": 1000000000,
    "active": 116444736000000000,
    "win_unix": 11644473600,
    "hfs_dec_sub": 2082844800,
    "kstime": 1400000000,
    "ticks": 621355968000000000,
}

# There have been no further leapseconds since 2017,1,1 at the __date__ of this script
# which is why the leapseconds end with a dt.now object to valid/relevant timestamp output.
# See REFERENCES.md for source info.
leapseconds = {
    10: [dt(1972, 1, 1, tzinfo=timezone.utc), dt(1972, 7, 1, tzinfo=timezone.utc)],
    11: [dt(1972, 7, 1, tzinfo=timezone.utc), dt(1973, 1, 1, tzinfo=timezone.utc)],
    12: [dt(1973, 1, 1, tzinfo=timezone.utc), dt(1974, 1, 1, tzinfo=timezone.utc)],
    13: [dt(1974, 1, 1, tzinfo=timezone.utc), dt(1975, 1, 1, tzinfo=timezone.utc)],
    14: [dt(1975, 1, 1, tzinfo=timezone.utc), dt(1976, 1, 1, tzinfo=timezone.utc)],
    15: [dt(1976, 1, 1, tzinfo=timezone.utc), dt(1977, 1, 1, tzinfo=timezone.utc)],
    16: [dt(1977, 1, 1, tzinfo=timezone.utc), dt(1978, 1, 1, tzinfo=timezone.utc)],
    17: [dt(1978, 1, 1, tzinfo=timezone.utc), dt(1979, 1, 1, tzinfo=timezone.utc)],
    18: [dt(1979, 1, 1, tzinfo=timezone.utc), dt(1980, 1, 1, tzinfo=timezone.utc)],
    19: [dt(1980, 1, 1, tzinfo=timezone.utc), dt(1981, 7, 1, tzinfo=timezone.utc)],
    20: [dt(1981, 7, 1, tzinfo=timezone.utc), dt(1982, 7, 1, tzinfo=timezone.utc)],
    21: [dt(1982, 7, 1, tzinfo=timezone.utc), dt(1983, 7, 1, tzinfo=timezone.utc)],
    22: [dt(1983, 7, 1, tzinfo=timezone.utc), dt(1985, 7, 1, tzinfo=timezone.utc)],
    23: [dt(1985, 7, 1, tzinfo=timezone.utc), dt(1988, 1, 1, tzinfo=timezone.utc)],
    24: [dt(1988, 1, 1, tzinfo=timezone.utc), dt(1990, 1, 1, tzinfo=timezone.utc)],
    25: [dt(1990, 1, 1, tzinfo=timezone.utc), dt(1991, 1, 1, tzinfo=timezone.utc)],
    26: [dt(1991, 1, 1, tzinfo=timezone.utc), dt(1992, 7, 1, tzinfo=timezone.utc)],
    27: [dt(1992, 7, 1, tzinfo=timezone.utc), dt(1993, 7, 1, tzinfo=timezone.utc)],
    28: [dt(1993, 7, 1, tzinfo=timezone.utc), dt(1994, 7, 1, tzinfo=timezone.utc)],
    29: [dt(1994, 7, 1, tzinfo=timezone.utc), dt(1996, 1, 1, tzinfo=timezone.utc)],
    30: [dt(1996, 1, 1, tzinfo=timezone.utc), dt(1997, 7, 1, tzinfo=timezone.utc)],
    31: [dt(1997, 7, 1, tzinfo=timezone.utc), dt(1999, 1, 1, tzinfo=timezone.utc)],
    32: [dt(1999, 1, 1, tzinfo=timezone.utc), dt(2006, 1, 1, tzinfo=timezone.utc)],
    33: [dt(2006, 1, 1, tzinfo=timezone.utc), dt(2009, 1, 1, tzinfo=timezone.utc)],
    34: [dt(2009, 1, 1, tzinfo=timezone.utc), dt(2012, 7, 1, tzinfo=timezone.utc)],
    35: [dt(2012, 7, 1, tzinfo=timezone.utc), dt(2015, 7, 1, tzinfo=timezone.utc)],
    36: [dt(2015, 7, 1, tzinfo=timezone.utc), dt(2017, 1, 1, tzinfo=timezone.utc)],
    37: [
        dt(2017, 1, 1, tzinfo=timezone.utc),
        dt.now(timezone.utc) - timedelta(seconds=37),
    ],
}

S32_CHARS = "234567abcdefghijklmnopqrstuvwxyz"
BASE32_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
URLSAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_"
KSALNUM_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def from_unixsec(timestamp):
    """Convert Unix Seconds value to a date"""
    ts_type, reason, _, tz_out = ts_types["unixsec"]
    try:
        if len(str(timestamp)) != 10 or not timestamp.isdigit():
            in_unix_sec = indiv_output = combined_output = ""
        else:
            in_unix_sec = dt.fromtimestamp(float(timestamp), timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(ts_type, in_unix_sec, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_unix_sec = indiv_output = combined_output = ""
    return in_unix_sec, indiv_output, combined_output, reason, tz_out


def to_unixsec(dt_obj):
    """Convert date to a Unix Seconds value"""
    ts_type, _, _, _ = ts_types["unixsec"]
    try:
        out_unix_sec = str(int(dt_obj.timestamp()))
        ts_output, _ = format_output(ts_type, out_unix_sec)
    except Exception:
        handle(sys.exc_info())
        out_unix_sec = ts_output = ""
    return out_unix_sec, ts_output


def from_unixmilli(timestamp):
    """Convert Unix Millisecond value to a date"""
    ts_type, reason, _, tz_out = ts_types["unixmilli"]
    try:
        if len(str(timestamp)) != 13 or not str(timestamp).isdigit():
            in_unix_milli = indiv_output = combined_output = ""
        else:
            in_unix_milli = dt.fromtimestamp(
                float(timestamp) / 1000.0, timezone.utc
            ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_unix_milli} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_milli} {tz_out}{__clr__}"
            )
            indiv_output, combined_output = format_output(
                ts_type, in_unix_milli, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_milli = indiv_output = combined_output = ""
    return in_unix_milli, indiv_output, combined_output, reason, tz_out


def to_unixmilli(dt_obj):
    """Convert date to a Unix Millisecond value"""
    ts_type, _, _, _ = ts_types["unixmilli"]
    try:
        out_unix_milli = str(int(dt_obj.timestamp() * 1000))
        ts_output, _ = format_output(ts_type, out_unix_milli)
    except Exception:
        handle(sys.exc_info())
        out_unix_milli = ts_output = ""
    return out_unix_milli, ts_output


def from_unixmillihex(timestamp):
    """Convert a Unix Millisecond hex value to a date"""
    ts_type, reason, _, tz_out = ts_types["unixmillihex"]
    try:
        if len(str(timestamp)) != 12 or not all(
            char in hexdigits for char in timestamp
        ):
            in_unix_milli_hex = indiv_output = combined_output = ""
        else:
            unix_mil = int(str(timestamp), 16)
            in_unix_milli_hex, _, _, _, _ = from_unixmilli(unix_mil)
            indiv_output, combined_output = format_output(
                ts_type, in_unix_milli_hex, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_milli_hex = indiv_output = combined_output = ""
    return in_unix_milli_hex, indiv_output, combined_output, reason, tz_out


def to_unixmillihex(dt_obj):
    """Convert a date to a Unix Millisecond hex value"""
    ts_type, _, _, _ = ts_types["unixmillihex"]
    try:
        unix_mil, _ = to_unixmilli(dt_obj)
        out_unix_milli_hex = f"{int(unix_mil):012x}"
        ts_output, _ = format_output(ts_type, out_unix_milli_hex)
    except Exception:
        handle(sys.exc_info())
        out_unix_milli_hex = ts_output = ""
    return out_unix_milli_hex, ts_output


def from_filetimebe(timestamp):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    ts_type, reason, _, tz_out = ts_types["filetimebe"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_filetime_be = indiv_output = combined_output = ""
        else:
            base10_microseconds = int(timestamp, 16) / 10
            if base10_microseconds >= 1e17:
                in_filetime_be = indiv_output = combined_output = ""
            else:
                dt_obj = epochs[1601] + timedelta(microseconds=base10_microseconds)
                in_filetime_be = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_filetime_be, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_filetime_be = indiv_output = combined_output = ""
    return in_filetime_be, indiv_output, combined_output, reason, tz_out


def to_filetimebe(dt_obj):
    """Convert a date to a Windows 64 Hex Big-Endian value"""
    ts_type, _, _, _ = ts_types["filetimebe"]
    try:
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + (minus_epoch.seconds * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        out_filetime_be = str(hex(int(calc_time) * 10))[2:].zfill(16)
        ts_output, _ = format_output(ts_type, out_filetime_be)
    except Exception:
        handle(sys.exc_info())
        out_filetime_be = ts_output = ""
    return out_filetime_be, ts_output


def from_filetimele(timestamp):
    """Convert a Windows 64 Hex Little-Endian value to a date"""
    ts_type, reason, _, tz_out = ts_types["filetimele"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_filetime_le = indiv_output = combined_output = ""
        else:
            indiv_output = combined_output = ""
            endianness_change = int.from_bytes(
                struct.pack("<Q", int(timestamp, 16)), "big"
            )
            converted_time = endianness_change / 10
            if converted_time >= 1e17:
                in_filetime_le = indiv_output = combined_output = ""
            else:
                dt_obj = epochs[1601] + timedelta(microseconds=converted_time)
                in_filetime_le = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_filetime_le, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_filetime_le = indiv_output = combined_output = ""
    return in_filetime_le, indiv_output, combined_output, reason, tz_out


def to_filetimele(dt_obj):
    """Convert a date to a Windows 64 Hex Little-Endian value"""
    ts_type, _, _, _ = ts_types["filetimele"]
    try:
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + (minus_epoch.seconds * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        out_filetime_le = str(struct.pack("<Q", int(calc_time * 10)).hex()).zfill(16)
        ts_output, _ = format_output(ts_type, out_filetime_le)
    except Exception:
        handle(sys.exc_info())
        out_filetime_le = ts_output = ""
    return out_filetime_le, ts_output


def from_chrome(timestamp):
    """Convert a Chrome Timestamp/Webkit Value to a date"""
    ts_type, reason, _, tz_out = ts_types["chrome"]
    try:
        if not len(timestamp) == 17 or not timestamp.isdigit():
            in_chrome = indiv_output = combined_output = ""
        else:
            delta = timedelta(microseconds=int(timestamp))
            converted_time = epochs[1601] + delta
            in_chrome = converted_time.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_chrome, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_chrome = indiv_output = combined_output = ""
    return in_chrome, indiv_output, combined_output, reason, tz_out


def to_chrome(dt_obj):
    """Convert a date to a Chrome Timestamp/Webkit value"""
    ts_type, _, _, _ = ts_types["chrome"]
    try:
        chrome_time = (dt_obj - epochs[1601]).total_seconds()
        out_chrome = str(int(chrome_time * 1000000))
        ts_output, _ = format_output(ts_type, out_chrome)
    except Exception:
        handle(sys.exc_info())
        out_chrome = ts_output = ""
    return out_chrome, ts_output


def from_active(timestamp):
    """Convert an Active Directory/LDAP timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["active"]
    try:
        if not len(timestamp) == 18 or not timestamp.isdigit():
            in_ad = indiv_output = combined_output = ""
        else:
            val_check = (
                float(int(timestamp) - epochs["active"]) / epochs["hundreds_nano"]
            )
            if val_check < 0 or val_check >= 32536799999:
                # This is the Windows maximum for parsing a unix TS
                # and is 3001-01-19 02:59:59 UTC
                in_ad = indiv_output = combined_output = ""
            else:
                dt_obj = dt.fromtimestamp(val_check, timezone.utc)
                in_ad = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(ts_type, in_ad, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ad = indiv_output = combined_output = ""
    return in_ad, indiv_output, combined_output, reason, tz_out


def to_active(dt_obj):
    """Convert a date to an Active Directory/LDAP timestamp"""
    ts_type, _, _, _ = ts_types["active"]
    try:
        nano_convert = int(dt_obj.timestamp() * epochs["hundreds_nano"])
        out_adtime = str(int(nano_convert) + int(epochs["active"]))
        ts_output, _ = format_output(ts_type, out_adtime)
    except Exception:
        handle(sys.exc_info())
        out_adtime = ts_output = ""
    return out_adtime, ts_output


def from_unixhex32be(timestamp):
    """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["unixhex32be"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_unix_hex_32 = indiv_output = combined_output = ""
        else:
            to_dec = int(timestamp, 16)
            in_unix_hex_32 = dt.fromtimestamp(float(to_dec), timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(
                ts_type, in_unix_hex_32, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_hex_32 = indiv_output = combined_output = ""
    return in_unix_hex_32, indiv_output, combined_output, reason, tz_out


def to_unixhex32be(dt_obj):
    """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
    ts_type, _, _, _ = ts_types["unixhex32be"]
    try:
        unix_time = int(dt_obj.timestamp())
        out_unix_hex_32 = str(struct.pack(">L", unix_time).hex())
        ts_output, _ = format_output(ts_type, out_unix_hex_32)
    except Exception:
        handle(sys.exc_info())
        out_unix_hex_32 = ts_output = ""
    return out_unix_hex_32, ts_output


def from_unixhex32le(timestamp):
    """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["unixhex32le"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_unix_hex_32le = indiv_output = combined_output = ""
        else:
            to_dec = int.from_bytes(struct.pack("<L", int(timestamp, 16)), "big")
            in_unix_hex_32le = dt.fromtimestamp(float(to_dec), timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(
                ts_type, in_unix_hex_32le, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_hex_32le = indiv_output = combined_output = ""
    return in_unix_hex_32le, indiv_output, combined_output, reason, tz_out


def to_unixhex32le(dt_obj):
    """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
    ts_type, _, _, _ = ts_types["unixhex32le"]
    try:
        unix_time = int((dt_obj - epochs[1970]).total_seconds())
        out_unix_hex_32le = str(struct.pack("<L", unix_time).hex())
        ts_output, _ = format_output(ts_type, out_unix_hex_32le)
    except Exception:
        handle(sys.exc_info())
        out_unix_hex_32le = ts_output = ""
    return out_unix_hex_32le, ts_output


def from_cookie(timestamp):
    """Convert an Internet Explorer timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["cookie"]
    try:
        if not ("," in timestamp) or not (
            timestamp.split(",")[0].isdigit() and timestamp.split(",")[1].isdigit()
        ):
            in_cookie = indiv_output = combined_output = ""
        else:
            low, high = [int(h, base=10) for h in timestamp.split(",")]
            calc = 10**-7 * (high * 2**32 + low) - epochs["win_unix"]
            if calc >= 32536799999 or calc < 0:
                in_cookie = indiv_output = combined_output = ""
            else:
                dt_obj = dt.fromtimestamp(calc, timezone.utc)
                in_cookie = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_cookie, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_cookie = indiv_output = combined_output = ""
    return in_cookie, indiv_output, combined_output, reason, tz_out


def to_cookie(dt_obj):
    """Convert a date to Internet Explorer timestamp values"""
    ts_type, _, _, _ = ts_types["cookie"]
    try:
        unix_time = int(dt_obj.timestamp())
        high = int(((unix_time + epochs["win_unix"]) * 10**7) / 2**32)
        low = (
            int((unix_time + epochs["win_unix"]) * 10**7)
            - (high * 2**32)
            + (dt_obj.microsecond * 10)
        )
        out_cookie = f"{str(low)},{str(high)}"
        ts_output, _ = format_output(ts_type, out_cookie)
    except Exception:
        handle(sys.exc_info())
        out_cookie = ts_output = ""
    return out_cookie, ts_output


def from_olebe(timestamp):
    """Convert an OLE Big-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["olebe"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_ole_be = indiv_output = combined_output = ""
        else:
            delta = struct.unpack(">d", struct.pack(">Q", int(timestamp, 16)))[0]
            if int(delta) < 0 or int(delta) > 2e6:
                in_ole_be = indiv_output = combined_output = ""
            else:
                dt_obj = epochs[1899] + timedelta(days=delta)
                in_ole_be = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_ole_be, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_ole_be = indiv_output = combined_output = ""
    return in_ole_be, indiv_output, combined_output, reason, tz_out


def to_olebe(dt_obj):
    """Convert a date to an OLE Big-Endian timestamp"""
    ts_type, _, _, _ = ts_types["olebe"]
    try:
        delta = ((dt_obj - epochs[1899]).total_seconds()) / 86400
        conv = struct.unpack("<Q", struct.pack("<d", delta))[0]
        out_ole_be = str(struct.pack(">Q", conv).hex())
        ts_output, _ = format_output(ts_type, out_ole_be)
    except Exception:
        handle(sys.exc_info())
        out_ole_be = ts_output = ""
    return out_ole_be, ts_output


def from_olele(timestamp):
    """Convert an OLE Little-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["olele"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_ole_le = indiv_output = combined_output = ""
        else:
            to_le = hex(int.from_bytes(struct.pack("<Q", int(timestamp, 16)), "big"))
            delta = struct.unpack(">d", struct.pack(">Q", int(to_le[2:], 16)))[0]
            if int(delta) < 0 or int(delta) > 99999:
                in_ole_le = indiv_output = combined_output = ""
            else:
                dt_obj = epochs[1899] + timedelta(days=delta)
                in_ole_le = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_ole_le, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_ole_le = indiv_output = combined_output = ""
    return in_ole_le, indiv_output, combined_output, reason, tz_out


def to_olele(dt_obj):
    """Convert a date to an OLE Little-Endian timestamp"""
    ts_type, _, _, _ = ts_types["olele"]
    try:
        delta = ((dt_obj - epochs[1899]).total_seconds()) / 86400
        conv = struct.unpack("<Q", struct.pack("<d", delta))[0]
        out_ole_le = str(struct.pack("<Q", conv).hex())
        ts_output, _ = format_output(ts_type, out_ole_le)
    except Exception:
        handle(sys.exc_info())
        out_ole_le = ts_output = ""
    return out_ole_le, ts_output


def from_bplist(timestamp):
    """Convert a bplist NSDate timestamp to a date value"""
    _, reason, _, tz_out = ts_types["bplist"]
    if len(timestamp) == 9 and timestamp.isdigit():
        in_nsdate, indiv_output, combined_output, reason, tz_out = from_nsdate(
            timestamp, "bplist"
        )
    else:
        in_nsdate = indiv_output = combined_output = ""
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def to_bplist(dt_obj):
    """Convert a date to a Binary Plist timestamp"""
    ts_type, _, _, _ = ts_types["bplist"]
    try:
        out_bplist = str(int((dt_obj - epochs[2001]).total_seconds()))
        if int(out_bplist) < 0:
            out_bplist = "[!] Timestamp Boundary Exceeded [!]"
        ts_output, _ = format_output(ts_type, out_bplist)
    except Exception:
        handle(sys.exc_info())
        out_bplist = ts_output = ""
    return out_bplist, ts_output


def from_iostime(timestamp):
    """Convert an iOS NSDate timestamp to a date value"""
    _, reason, _, tz_out = ts_types["iostime"]
    if len(timestamp) in range(15, 19) and timestamp.isdigit():
        in_nsdate, indiv_output, combined_output, reason, tz_out = from_nsdate(
            timestamp, "iostime"
        )
    else:
        in_nsdate = indiv_output = combined_output = ""
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def to_iostime(dt_obj):
    """Convert a date to an iOS 11 timestamp"""
    ts_type, _, _, _ = ts_types["iostime"]
    try:
        out_iostime = str(
            int(((dt_obj - epochs[2001]).total_seconds()) * epochs["nano_2001"])
        )
        if int(out_iostime) < 0:
            out_iostime = "[!] Timestamp Boundary Exceeded [!]"
        ts_output, _ = format_output(ts_type, out_iostime)
    except Exception:
        handle(sys.exc_info())
        out_iostime = ts_output = ""
    return out_iostime, ts_output


def from_mac(timestamp):
    """Convert a mac NSDate timestamp to a date value"""
    _, reason, _, tz_out = ts_types["mac"]
    if (
        "." in timestamp
        and (
            (len(timestamp.split(".")[0]) == 9)
            and (len(timestamp.split(".")[1]) in range(0, 7))
        )
        and "".join(timestamp.split(".")).isdigit()
    ):
        in_nsdate, indiv_output, combined_output, reason, tz_out = from_nsdate(
            timestamp, "mac"
        )
    else:
        in_nsdate = indiv_output = combined_output = ""
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def to_mac(dt_obj):
    """Convert a date to a Mac Absolute timestamp"""
    ts_type, _, _, _ = ts_types["mac"]
    try:
        mac_ts = (
            int(((dt_obj - epochs[2001]).total_seconds()) * epochs["nano_2001"])
            / 1000000000
        )
        if mac_ts < 0:
            out_mac = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_mac = str(f"{mac_ts:.6f}")
        ts_output, _ = format_output(ts_type, out_mac)
    except Exception:
        handle(sys.exc_info())
        out_mac = ts_output = ""
    return out_mac, ts_output


def from_nsdate(timestamp, val_type):
    """Convert an Apple NSDate timestamp (Mac Absolute, BPlist, Cocoa, iOS) to a date"""
    ts_type, reason, _, tz_out = ts_types[val_type]
    in_nsdate = indiv_output = combined_output = ""
    try:
        if val_type in {"mac", "bplist"}:
            try:
                dt_obj = epochs[2001] + timedelta(seconds=float(timestamp))
            except (ValueError, OverflowError):
                in_nsdate = indiv_output = combined_output = ""
                return in_nsdate, indiv_output, combined_output, reason, tz_out
            in_nsdate = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_nsdate, tz_out)
        elif val_type == "iostime":
            try:
                dt_obj = (int(timestamp) / int(epochs["nano_2001"])) + 978307200
            except (ValueError, OverflowError):
                in_nsdate = indiv_output = combined_output = ""
                return in_nsdate, indiv_output, combined_output, reason, tz_out
            in_nsdate = dt.fromtimestamp(dt_obj, timezone.utc).strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_nsdate, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_nsdate = indiv_output = combined_output = ""
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def from_hfsdec(timestamp):
    """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["hfsdec"]
    try:
        if len(str(timestamp)) != 10 or not (timestamp).isdigit():
            in_hfs_dec = indiv_output = combined_output = ""
        else:
            minus_epoch = float(int(timestamp) - epochs["hfs_dec_sub"])
            if minus_epoch < 0:
                in_hfs_dec = indiv_output = combined_output = ""
            else:
                in_hfs_dec = dt.fromtimestamp(minus_epoch, timezone.utc).strftime(
                    __fmt__
                )
                indiv_output, combined_output = format_output(
                    ts_type, in_hfs_dec, tz_out
                )
    except Exception:
        in_hfs_dec = indiv_output = combined_output = ""
        handle(sys.exc_info())
    return in_hfs_dec, indiv_output, combined_output, reason, tz_out


def to_hfsdec(dt_obj):
    """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
    ts_type, _, _, _ = ts_types["hfsdec"]
    try:
        out_hfs_dec = str(int((dt_obj - epochs[1904]).total_seconds()))
        ts_output, _ = format_output(ts_type, out_hfs_dec)
    except Exception:
        handle(sys.exc_info())
        out_hfs_dec = ts_output = ""
    return out_hfs_dec, ts_output


def from_hfsbe(timestamp):
    """Convert an HFS/HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
    ts_type, reason, _, tz_out = ts_types["hfsbe"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_hfs_be = indiv_output = combined_output = ""
        else:
            dt_obj = epochs[1904] + timedelta(seconds=int(timestamp, 16))
            in_hfs_be = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_hfs_be, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_hfs_be = indiv_output = combined_output = ""
    return in_hfs_be, indiv_output, combined_output, reason, tz_out


def to_hfsbe(dt_obj):
    """Convert a date to an HFS/HFS+ Big-Endian timestamp"""
    ts_type, _, _, _ = ts_types["hfsbe"]
    try:
        conv = int((dt_obj - epochs[1904]).total_seconds())
        if conv > 4294967295:
            out_hfs_be = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_hfs_be = f"{conv:08x}"
        ts_output, _ = format_output(ts_type, out_hfs_be)
    except Exception:
        handle(sys.exc_info())
        out_hfs_be = ts_output = ""
    return out_hfs_be, ts_output


def from_hfsle(timestamp):
    """Convert an HFS/HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
    ts_type, reason, _, tz_out = ts_types["hfsle"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_hfs_le = indiv_output = combined_output = ""
        else:
            to_le = struct.unpack(">I", struct.pack("<I", int(timestamp, 16)))[0]
            dt_obj = epochs[1904] + timedelta(seconds=to_le)
            in_hfs_le = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_hfs_le, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_hfs_le = indiv_output = combined_output = ""
    return in_hfs_le, indiv_output, combined_output, reason, tz_out


def to_hfsle(dt_obj):
    """Convert a date to an HFS/HFS+ Little-Endian timestamp"""
    ts_type, _, _, _ = ts_types["hfsle"]
    try:
        conv = int((dt_obj - epochs[1904]).total_seconds())
        if conv > 4294967295:
            out_hfs_le = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_hfs_le = str(struct.pack("<I", conv).hex())
        ts_output, _ = format_output(ts_type, out_hfs_le)
    except Exception:
        handle(sys.exc_info())
        out_hfs_le = ts_output = ""
    return out_hfs_le, ts_output


def from_fat(timestamp):
    """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["fat"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_fat = indiv_output = combined_output = ""
        else:
            byte_swap = [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)]
            to_le = byte_swap[1] + byte_swap[0] + byte_swap[3] + byte_swap[2]
            binary = f"{int(to_le, 16):032b}"
            stamp = [
                binary[:7],
                binary[7:11],
                binary[11:16],
                binary[16:21],
                binary[21:27],
                binary[27:32],
            ]
            for binary in stamp[:]:
                dec = int(binary, 2)
                stamp.remove(binary)
                stamp.append(dec)
            fat_year = stamp[0] + 1980
            fat_month = stamp[1]
            fat_day = stamp[2]
            fat_hour = stamp[3]
            fat_min = stamp[4]
            fat_sec = stamp[5] * 2
            try:
                out_of_range = any(
                    not low <= value < high
                    for value, (low, high) in zip(
                        (fat_year, fat_month, fat_day, fat_hour, fat_min, fat_sec),
                        (
                            (1970, 2100),
                            (1, 13),
                            (1, monthrange(fat_year, fat_month)[1] + 1),
                            (0, 24),
                            (0, 60),
                            (0, 60),
                        ),
                    )
                )
                if out_of_range:
                    in_fat = indiv_output = combined_output = ""
                    return in_fat, indiv_output, combined_output, reason, tz_out
            except (IllegalMonthError, ValueError):
                in_fat = indiv_output = combined_output = ""
                return in_fat, indiv_output, combined_output, reason, tz_out
            dt_obj = dt(fat_year, fat_month, fat_day, fat_hour, fat_min, fat_sec)
            in_fat = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_fat, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_fat = indiv_output = combined_output = ""
    return in_fat, indiv_output, combined_output, reason, tz_out


def to_fat(dt_obj):
    """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
    ts_type, _, _, _ = ts_types["fat"]
    try:
        year = f"{(dt_obj.year - 1980):07b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        seconds = f"{int(dt_obj.second / 2):05b}"
        to_hex = str(
            struct.pack(
                ">I", int(year + month + day + hour + minute + seconds, 2)
            ).hex()
        )
        byte_swap = "".join([to_hex[i : i + 2] for i in range(0, len(to_hex), 2)][::-1])
        out_fat = "".join(
            [byte_swap[i : i + 4] for i in range(0, len(byte_swap), 4)][::-1]
        )
        ts_output, _ = format_output(ts_type, out_fat)
    except Exception:
        handle(sys.exc_info())
        out_fat = ts_output = ""
    return out_fat, ts_output


def from_msdos(timestamp):
    """Convert an MS-DOS timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["msdos"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_msdos = indiv_output = combined_output = ""
        else:
            swap = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            binary = f"{int(swap, 16):032b}"
            stamp = [
                binary[:7],
                binary[7:11],
                binary[11:16],
                binary[16:21],
                binary[21:27],
                binary[27:32],
            ]
            for val in stamp[:]:
                dec = int(val, 2)
                stamp.remove(val)
                stamp.append(dec)
            dos_year = stamp[0] + 1980
            dos_month = stamp[1]
            dos_day = stamp[2]
            dos_hour = stamp[3]
            dos_min = stamp[4]
            dos_sec = stamp[5] * 2
            try:
                out_of_range = any(
                    not low <= value < high
                    for value, (low, high) in zip(
                        (dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec),
                        (
                            (1970, 2100),
                            (1, 13),
                            (1, monthrange(dos_year, dos_month)[1] + 1),
                            (0, 24),
                            (0, 60),
                            (0, 60),
                        ),
                    )
                )
                if out_of_range:
                    in_msdos = indiv_output = combined_output = ""
                    return in_msdos, indiv_output, combined_output, reason, tz_out
            except (IllegalMonthError, ValueError):
                in_msdos = indiv_output = combined_output = ""
                return in_msdos, indiv_output, combined_output, reason, tz_out
            dt_obj = dt(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec)
            in_msdos = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_msdos, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_msdos = indiv_output = combined_output = ""
    return in_msdos, indiv_output, combined_output, reason, tz_out


def to_msdos(dt_obj):
    """Convert a date to an MS-DOS timestamp"""
    ts_type, _, _, _ = ts_types["msdos"]
    try:
        year = f"{(dt_obj.year - 1980):07b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        seconds = f"{int(dt_obj.second / 2):05b}"
        hexval = str(
            struct.pack(
                ">I", int(year + month + day + hour + minute + seconds, 2)
            ).hex()
        )
        out_msdos = "".join([hexval[i : i + 2] for i in range(0, len(hexval), 2)][::-1])
        ts_output, _ = format_output(ts_type, out_msdos)
    except Exception:
        handle(sys.exc_info())
        out_msdos = ts_output = ""
    return out_msdos, ts_output


def from_exfat(timestamp):
    """Convert an exFAT timestamp (LE) to a date"""
    ts_type, reason, _, tz_out = ts_types["exfat"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_exfat = indiv_output = combined_output = ""
        else:
            binary = f"{int(timestamp, 16):032b}"
            stamp = [
                binary[:7],
                binary[7:11],
                binary[11:16],
                binary[16:21],
                binary[21:27],
                binary[27:32],
            ]
            for val in stamp[:]:
                dec = int(val, 2)
                stamp.remove(val)
                stamp.append(dec)
            exfat_year = stamp[0] + 1980
            exfat_month = stamp[1]
            exfat_day = stamp[2]
            exfat_hour = stamp[3]
            exfat_min = stamp[4]
            exfat_sec = stamp[5] * 2
            try:
                out_of_range = any(
                    not low <= value < high
                    for value, (low, high) in zip(
                        (
                            exfat_year,
                            exfat_month,
                            exfat_day,
                            exfat_hour,
                            exfat_min,
                            exfat_sec,
                        ),
                        (
                            (1970, 2100),
                            (1, 13),
                            (1, monthrange(exfat_year, exfat_month)[1] + 1),
                            (0, 24),
                            (0, 60),
                            (0, 60),
                        ),
                    )
                )
                if out_of_range:
                    in_exfat = indiv_output = combined_output = ""
                    return in_exfat, indiv_output, combined_output, reason, tz_out
            except (IllegalMonthError, ValueError):
                in_exfat = indiv_output = combined_output = ""
                return in_exfat, indiv_output, combined_output, reason, tz_out
            dt_obj = dt(
                exfat_year, exfat_month, exfat_day, exfat_hour, exfat_min, exfat_sec
            )
            in_exfat = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_exfat, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_exfat = indiv_output = combined_output = ""
    return in_exfat, indiv_output, combined_output, reason, tz_out


def to_exfat(dt_obj):
    """Convert a date to an exFAT timestamp (LE)"""
    ts_type, _, _, _ = ts_types["exfat"]
    try:
        year = f"{(dt_obj.year - 1980):07b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        seconds = f"{int(dt_obj.second / 2):05b}"
        out_exfat = str(
            struct.pack(
                ">I", int(year + month + day + hour + minute + seconds, 2)
            ).hex()
        )
        ts_output, _ = format_output(ts_type, out_exfat)
    except Exception:
        handle(sys.exc_info())
        out_exfat = ts_output = ""
    return out_exfat, ts_output


def from_systemtime(timestamp):
    """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["systemtime"]
    try:
        if not len(timestamp) == 32 or not all(char in hexdigits for char in timestamp):
            in_systemtime = indiv_output = combined_output = ""
        else:
            to_le = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            converted = [to_le[i : i + 4] for i in range(0, len(to_le), 4)][::-1]
            stamp = []
            for i in converted:
                dec = int(i, 16)
                stamp.append(dec)
            if (stamp[0] > 3000) or (stamp[1] > 12) or (stamp[2] > 31):
                in_systemtime = indiv_output = combined_output = ""
            else:
                dt_obj = dt(
                    stamp[0],
                    stamp[1],
                    stamp[3],
                    stamp[4],
                    stamp[5],
                    stamp[6],
                    stamp[7] * 1000,
                )
                in_systemtime = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(
                ts_type, in_systemtime, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_systemtime = indiv_output = combined_output = ""
    return in_systemtime, indiv_output, combined_output, reason, tz_out


def to_systemtime(dt_obj):
    """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
    ts_type, _, _, _ = ts_types["systemtime"]
    try:
        micro = int(dt_obj.microsecond / 1000)
        full_date = dt_obj.strftime(f"%Y, %m, %w, %d, %H, %M, %S, {micro}")
        stamp = []
        for val in full_date.split(","):
            to_hex = int(
                hex(int.from_bytes(struct.pack("<H", int(val)), "big"))[2:], 16
            )
            stamp.append(f"{to_hex:04x}")
        out_systemtime = "".join(stamp)
        ts_output, _ = format_output(ts_type, out_systemtime)
    except Exception:
        handle(sys.exc_info())
        out_systemtime = ts_output = ""
    return out_systemtime, ts_output


def from_filetimelohi(timestamp):
    """Convert a Microsoft FILETIME timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["filetimelohi"]
    try:
        if not (":" in timestamp) or not (
            all(char in hexdigits for char in timestamp[0:8])
            and all(char in hexdigits for char in timestamp[9:])
        ):
            in_filetime_lo_hi = indiv_output = combined_output = ""
        else:
            part2, part1 = [int(h, base=16) for h in timestamp.split(":")]
            converted_time = struct.unpack(">Q", struct.pack(">LL", part1, part2))[0]
            if converted_time >= 1e18:
                in_filetime_lo_hi = indiv_output = combined_output = ""
            else:
                dt_obj = dt.fromtimestamp(
                    float(converted_time - epochs["active"]) / epochs["hundreds_nano"],
                    timezone.utc,
                )
                in_filetime_lo_hi = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_filetime_lo_hi, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_filetime_lo_hi = indiv_output = combined_output = ""
    return in_filetime_lo_hi, indiv_output, combined_output, reason, tz_out


def to_filetimelohi(dt_obj):
    """Convert a date to a Microsoft FILETIME timestamp"""
    ts_type, _, _, _ = ts_types["filetimelohi"]
    try:
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + (minus_epoch.seconds * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        indiv_output = str(struct.pack(">Q", int(calc_time * 10)).hex())
        out_filetime_lo_hi = f"{str(indiv_output[8:])}:{str(indiv_output[:8])}"
        ts_output, _ = format_output(ts_type, out_filetime_lo_hi)
    except Exception:
        handle(sys.exc_info())
        out_filetime_lo_hi = ts_output = ""
    return out_filetime_lo_hi, ts_output


def from_hotmail(timestamp):
    """Convert a Microsoft Hotmail timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["hotmail"]
    try:
        if ":" not in timestamp or not (
            all(char in hexdigits for char in timestamp[0:8])
            and all(char in hexdigits for char in timestamp[9:])
        ):
            in_hotmail = indiv_output = combined_output = ""
        else:
            hm_repl = timestamp.replace(":", "")
            byte_swap = "".join(
                [hm_repl[i : i + 2] for i in range(0, len(hm_repl), 2)][::-1]
            )
            part2 = int(byte_swap[:8], base=16)
            part1 = int(byte_swap[8:], base=16)
            converted_time = struct.unpack(">Q", struct.pack(">LL", part1, part2))[0]
            if converted_time >= 1e18:
                in_hotmail = indiv_output = combined_output = ""
            else:
                dt_obj = dt.fromtimestamp(
                    float(converted_time - epochs["active"]) / epochs["hundreds_nano"],
                    timezone.utc,
                )
                in_hotmail = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_hotmail, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_hotmail = indiv_output = combined_output = ""
    return in_hotmail, indiv_output, combined_output, reason, tz_out


def to_hotmail(dt_obj):
    """Convert a date to a Microsoft Hotmail timestamp"""
    ts_type, _, _, _ = ts_types["hotmail"]
    try:
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + (minus_epoch.seconds * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        indiv_output = str(struct.pack(">Q", int(calc_time * 10)).hex())
        byte_swap = "".join(
            [indiv_output[i : i + 2] for i in range(0, len(indiv_output), 2)][::-1]
        )
        out_hotmail = f"{str(byte_swap[8:])}:{str(byte_swap[:8])}"
        ts_output, _ = format_output(ts_type, out_hotmail)
    except Exception:
        handle(sys.exc_info())
        out_hotmail = ts_output = ""
    return out_hotmail, ts_output


def from_prtime(timestamp):
    """Convert a Mozilla PRTime timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["prtime"]
    try:
        if not len(timestamp) == 16 or not timestamp.isdigit():
            in_prtime = indiv_output = combined_output = ""
        else:
            dt_obj = epochs[1970] + timedelta(microseconds=int(timestamp))
            in_prtime = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_prtime, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_prtime = indiv_output = combined_output = ""
    return in_prtime, indiv_output, combined_output, reason, tz_out


def to_prtime(dt_obj):
    """Convert a date to Mozilla's PRTime timestamp"""
    ts_type, _, _, _ = ts_types["prtime"]
    try:
        out_prtime = str(int(((dt_obj - epochs[1970]).total_seconds()) * 1000000))
        ts_output, _ = format_output(ts_type, out_prtime)
    except Exception:
        handle(sys.exc_info())
        out_prtime = ts_output = ""
    return out_prtime, ts_output


def from_oleauto(timestamp):
    """Convert an OLE Automation timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["oleauto"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 5)
                and (len(timestamp.split(".")[1]) in range(9, 13))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_ole_auto = indiv_output = combined_output = ""
        else:
            dt_obj = epochs[1899] + timedelta(days=float(timestamp))
            in_ole_auto = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_ole_auto, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ole_auto = indiv_output = combined_output = ""
    return in_ole_auto, indiv_output, combined_output, reason, tz_out


def to_oleauto(dt_obj):
    """Convert a date to an OLE Automation timestamp"""
    ts_type, _, _, _ = ts_types["oleauto"]
    try:
        ole_ts = ((dt_obj - epochs[1899]).total_seconds()) / 86400
        out_ole_auto = f"{ole_ts:.12f}"
        ts_output, _ = format_output(ts_type, out_ole_auto)
    except Exception:
        handle(sys.exc_info())
        out_ole_auto = ts_output = ""
    return out_ole_auto, ts_output


def from_ms1904(timestamp):
    """Convert a Microsoft Excel 1904 timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["ms1904"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 5)
                and (len(timestamp.split(".")[1]) in range(9, 13))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_ms1904 = indiv_output = combined_output = ""
        else:
            dt_obj = epochs[1904] + timedelta(days=float(timestamp))
            in_ms1904 = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_ms1904, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ms1904 = indiv_output = combined_output = ""
    return in_ms1904, indiv_output, combined_output, reason, tz_out


def to_ms1904(dt_obj):
    """Convert a date to a Microsoft Excel 1904 timestamp"""
    ts_type, _, _, _ = ts_types["ms1904"]
    try:
        ms1904_ts = ((dt_obj - epochs[1904]).total_seconds()) / 86400
        out_ms1904 = f"{ms1904_ts:.12f}"
        ts_output, _ = format_output(ts_type, out_ms1904)
    except Exception:
        handle(sys.exc_info())
        out_ms1904 = ts_output = ""
    return out_ms1904, ts_output


def from_symantec(timestamp):
    """Convert a Symantec 6-byte hex timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["symantec"]
    try:
        if not len(timestamp) == 12 or not all(char in hexdigits for char in timestamp):
            in_symtime = indiv_output = combined_output = ""
        else:
            hex_to_dec = [
                int(timestamp[i : i + 2], 16) for i in range(0, len(timestamp), 2)
            ]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            hex_to_dec[1] = hex_to_dec[1] + 1
            if hex_to_dec[1] not in range(1, 13):
                in_symtime = indiv_output = combined_output = ""
            else:
                try:
                    dt_obj = dt(
                        hex_to_dec[0],
                        hex_to_dec[1],
                        hex_to_dec[2],
                        hex_to_dec[3],
                        hex_to_dec[4],
                        hex_to_dec[5],
                    )
                except ValueError:
                    in_symtime = indiv_output = combined_output = ""
                    return in_symtime, indiv_output, combined_output, reason, tz_out
                in_symtime = dt_obj.strftime(__fmt__)
        indiv_output, combined_output = format_output(ts_type, in_symtime, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_symtime = indiv_output = combined_output = ""
    return in_symtime, indiv_output, combined_output, reason, tz_out


def to_symantec(dt_obj):
    """Convert a date to Symantec's 6-byte hex timestamp"""
    ts_type, _, _, _ = ts_types["symantec"]
    try:
        sym_year = f"{(dt_obj.year - 1970):02x}"
        sym_month = f"{(dt_obj.month - 1):02x}"
        sym_day = f"{(dt_obj.day):02x}"
        sym_hour = f"{(dt_obj.hour):02x}"
        sym_minute = f"{(dt_obj.minute):02x}"
        sym_second = f"{(dt_obj.second):02x}"
        out_symtime = (
            f"{sym_year}{sym_month}{sym_day}{sym_hour}{sym_minute}{sym_second}"
        )
        ts_output, _ = format_output(ts_type, out_symtime)
    except Exception:
        handle(sys.exc_info())
        out_symtime = ts_output = ""
    return out_symtime, ts_output


def from_gps(timestamp):
    """Convert a GPS timestamp to a date (involves leap seconds)"""
    ts_type, reason, _, tz_out = ts_types["gps"]
    try:
        if not len(timestamp) == 10 or not timestamp.isdigit():
            in_gpstime = indiv_output = combined_output = ""
        else:
            gps_stamp = epochs[1980] + timedelta(seconds=float(timestamp))
            tai_convert = gps_stamp + timedelta(seconds=19)
            epoch_convert = (tai_convert - epochs[1970]).total_seconds()
            check_date = dt.fromtimestamp(epoch_convert, timezone.utc)
            for entry in leapseconds:
                check = date_range(
                    leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date
                )
                if check is True:
                    variance = entry
                else:
                    variance = 0
            gps_out = check_date - timedelta(seconds=variance)
            in_gpstime = gps_out.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_gpstime, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_gpstime = indiv_output = combined_output = ""
    return in_gpstime, indiv_output, combined_output, reason, tz_out


def to_gps(dt_obj):
    """Convert a date to a GPS timestamp (involves leap seconds)"""
    ts_type, _, _, _ = ts_types["gps"]
    try:
        for entry in leapseconds:
            check = date_range(
                leapseconds.get(entry)[0], leapseconds.get(entry)[1], dt_obj
            )
            if check is True:
                variance = entry
            else:
                variance = 0
        leap_correction = dt_obj + timedelta(seconds=variance)
        epoch_shift = leap_correction - epochs[1970]
        gps_stamp = (
            dt.fromtimestamp(epoch_shift.total_seconds(), timezone.utc) - epochs[1980]
        ).total_seconds() - 19
        out_gpstime = str(int(gps_stamp))
        ts_output, _ = format_output(ts_type, out_gpstime)
    except Exception:
        handle(sys.exc_info())
        out_gpstime = ts_output = ""
    return out_gpstime, ts_output


def from_eitime(timestamp):
    """Convert a Google ei URL timestamp"""
    ts_type, reason, _, tz_out = ts_types["eitime"]
    try:
        if not all(char in URLSAFE_CHARS for char in timestamp):
            in_eitime = indiv_output = combined_output = ""
        else:
            padding_check = len(timestamp) % 4
            if padding_check != 0:
                padding_reqd = 4 - padding_check
                result_eitime = timestamp + (padding_reqd * "=")
            else:
                result_eitime = timestamp
            try:
                decoded_eitime = base64.urlsafe_b64decode(result_eitime).hex()[:8]
                unix_ts = int.from_bytes(
                    struct.pack("<L", int(decoded_eitime, 16)), "big"
                )
                in_eitime = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_eitime, tz_out
                )
            except base64.binascii.Error:
                in_eitime = indiv_output = combined_output = ""
    except Exception:
        handle(sys.exc_info())
        in_eitime = indiv_output = combined_output = ""
    return in_eitime, indiv_output, combined_output, reason, tz_out


def to_eitime(dt_obj):
    """Try to convert a value to an ei URL timestamp"""
    ts_type, _, _, _ = ts_types["eitime"]
    try:
        unix_time = int((dt_obj - epochs[1970]).total_seconds())
        unix_hex = struct.pack("<L", unix_time)
        urlsafe_encode = base64.urlsafe_b64encode(unix_hex)
        out_eitime = urlsafe_encode.decode(encoding="UTF-8").strip("=")
        ts_output, _ = format_output(ts_type, out_eitime)
    except Exception:
        handle(sys.exc_info())
        out_eitime = ts_output = ""
    return out_eitime, ts_output


def from_gsm(timestamp):
    """Convert a GSM timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["gsm"]
    # The last byte of the GSM timestamp is a hex representation of the timezone.
    # If the timezone bitwise operation on this byte results in a timezone offset
    # of less than -12 or greater than 12, then the value is incorrect.
    # The values in tz_in_range are hex bytes which return proper timezones.
    tz_in_range = [
        "00",
        "01",
        "02",
        "03",
        "04",
        "05",
        "06",
        "07",
        "08",
        "09",
        "0a",
        "0b",
        "0c",
        "0d",
        "0e",
        "0f",
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "17",
        "18",
        "19",
        "20",
        "21",
        "22",
        "23",
        "24",
        "25",
        "26",
        "27",
        "28",
        "29",
        "30",
        "31",
        "32",
        "33",
        "34",
        "35",
        "36",
        "37",
        "38",
        "39",
        "40",
        "41",
        "42",
        "43",
        "44",
        "45",
        "46",
        "47",
        "48",
        "80",
        "81",
        "82",
        "83",
        "84",
        "85",
        "86",
        "87",
        "88",
        "89",
        "8a",
        "8b",
        "8c",
        "8d",
        "8e",
        "8f",
        "90",
        "91",
        "92",
        "93",
        "94",
        "95",
        "96",
        "97",
        "98",
        "99",
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
        "a7",
        "a8",
        "a9",
        "b0",
        "b1",
        "b2",
        "b3",
        "b4",
        "b5",
        "b6",
        "b7",
        "b8",
        "b9",
        "c0",
        "c1",
        "c2",
        "c3",
        "c4",
        "c5",
        "c6",
        "c7",
        "c8",
    ]
    try:
        tz_check = timestamp[12:14][::-1].lower()
        if (
            not len(timestamp) == 14
            or not all(char in hexdigits for char in timestamp)
            or tz_check not in tz_in_range
        ):
            in_gsm = indiv_output = combined_output = ""
        else:
            utc_offset = None
            swap = [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)]
            for value in swap[:]:
                l_endian = value[::-1]
                swap.remove(value)
                swap.append(l_endian)
            ts_tz = f"{int(swap[6], 16):08b}"
            if int(ts_tz[0]) == 1:
                utc_offset = (
                    -int(str(int(ts_tz[1:4], 2)) + str(int(ts_tz[4:8], 2))) * 0.25
                )
            elif int(ts_tz[0]) == 0:
                utc_offset = (
                    int(str(int(ts_tz[0:4], 2)) + str(int(ts_tz[4:8], 2))) * 0.25
                )
            swap[6] = utc_offset
            for string in swap[:]:
                swap.remove(string)
                swap.append(int(string))
            dt_year, dt_month, dt_day, dt_hour, dt_min, dt_sec, dt_tz = swap
            if dt_year in range(0, 50):
                dt_year = dt_year + 2000
            if dt_tz == 0:
                tz_out = f"{tz_out}"
            elif dt_tz > 0:
                tz_out = f"{tz_out}+{str(dt_tz)}"
            else:
                tz_out = f"{tz_out}{str(dt_tz)}"
            in_gsm = str(
                dt(dt_year, dt_month, dt_day, dt_hour, dt_min, dt_sec).strftime(__fmt__)
            )
            indiv_output, combined_output = format_output(ts_type, in_gsm, tz_out)
    except ValueError:
        in_gsm = indiv_output = combined_output = ""
    except Exception:
        handle(sys.exc_info())
        in_gsm = indiv_output = combined_output = ""
    return in_gsm, indiv_output, combined_output, reason, tz_out


def to_gsm(dt_obj):
    """Convert a timestamp to a GSM timestamp"""
    ts_type, _, _, _ = ts_types["gsm"]
    try:
        dt_tz = dt_obj.utcoffset().seconds
        if dt_tz == 0:
            hex_tz = f"{0:02d}"
        elif dt_tz < 0:
            dt_tz = dt_tz / 3600
            conversion = str(f"{(int(abs(dt_tz)) * 4):02d}")
            conv_list = list(conversion)
            high_order = f"{int(conv_list[0]):04b}"
            low_order = f"{int(conv_list[1]):04b}"
            high_order = f"{(int(high_order, 2) + 8):04b}"
            hex_tz = hex(int((high_order + low_order), 2)).lstrip("0x").upper()
        else:
            dt_tz = dt_tz / 3600
            conversion = str(int(dt_tz) * 4).zfill(2)
            conv_list = list(conversion)
            high_order = f"{int(conv_list[0]):04b}"
            low_order = f"{int(conv_list[1]):04b}"
            hex_tz = hex(int((high_order + low_order), 2)).lstrip("0x").upper()
        date_list = [
            f"{(dt_obj.year - 2000):02d}",
            f"{dt_obj.month:02d}",
            f"{dt_obj.day:02d}",
            f"{dt_obj.hour:02d}",
            f"{dt_obj.minute:02d}",
            f"{dt_obj.second:02d}",
            hex_tz,
        ]
        date_value_swap = []
        for value in date_list[:]:
            b_endian = value[::-1]
            date_value_swap.append(b_endian)
        out_gsm = "".join(date_value_swap)
        ts_output, _ = format_output(ts_type, out_gsm)
    except Exception:
        handle(sys.exc_info())
        out_gsm = ts_output = ""
    return out_gsm, ts_output


def from_vm(timestamp):
    """Convert from a .vmsd createTimeHigh/createTimeLow timestamp"""
    ts_type, reason, _, tz_out = ts_types["vm"]
    try:
        if "," not in timestamp:
            in_vm = indiv_output = combined_output = ""
        else:
            create_time_high = int(timestamp.split(",")[0])
            create_time_low = int(timestamp.split(",")[1])
            try:
                vmsd = (
                    float(
                        (create_time_high * 2**32)
                        + struct.unpack("I", struct.pack("i", create_time_low))[0]
                    )
                    / 1000000
                )
            except Exception:
                in_vm = indiv_output = combined_output = ""
                return in_vm, indiv_output, combined_output, reason, tz_out
            if vmsd >= 32536799999:
                in_vm = indiv_output = combined_output = ""
            else:
                in_vm = dt.fromtimestamp(vmsd, timezone.utc).strftime(__fmt__)
                indiv_output, combined_output = format_output(ts_type, in_vm, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_vm = indiv_output = combined_output = ""
    return in_vm, indiv_output, combined_output, reason, tz_out


def to_vm(dt_obj):
    """Convert date to a .vmsd createTime* value"""
    ts_type, _, _, _ = ts_types["vm"]
    try:
        unix_seconds = int((dt_obj - epochs[1970]).total_seconds()) * 1000000
        create_time_high = int(float(unix_seconds) / 2**32)
        unpacked_int = unix_seconds - (create_time_high * 2**32)
        create_time_low = struct.unpack("i", struct.pack("I", unpacked_int))[0]
        out_vm = f"{str(create_time_high)},{str(create_time_low)}"
        ts_output, _ = format_output(ts_type, out_vm)
    except Exception:
        handle(sys.exc_info())
        out_vm = ts_output = ""
    return out_vm, ts_output


def from_tiktok(timestamp):
    """Convert a TikTok URL value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["tiktok"]
    try:
        if len(str(timestamp)) < 19 or not timestamp.isdigit():
            in_tiktok = indiv_output = combined_output = ""
        else:
            unix_ts = int(timestamp) >> 32
            if unix_ts >= 32536799999:
                in_tiktok = indiv_output = combined_output = ""
            else:
                in_tiktok = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                    __fmt__
                )
            indiv_output, combined_output = format_output(ts_type, in_tiktok, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_tiktok = indiv_output = combined_output = ""
    return in_tiktok, indiv_output, combined_output, reason, tz_out


def to_tiktok(dt_obj):
    """Convert a date/time to a TikTok timestamp"""
    ts_type, _, _, _ = ts_types["tiktok"]
    try:
        unix_ts = int(dt_obj.timestamp())
        out_tiktok = str(unix_ts << 32)
        ts_output, _ = format_output(ts_type, out_tiktok)
    except Exception:
        handle(sys.exc_info())
        out_tiktok = ts_output = ""
    return out_tiktok, ts_output


def from_twitter(timestamp):
    """Convert a Twitter URL value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["twitter"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_twitter = indiv_output = combined_output = ""
        else:
            unix_ts = ((int(timestamp) >> 22) + 1288834974657) / 1000
            if unix_ts >= 32536799999:
                in_twitter = indiv_output = combined_output = ""
            else:
                in_twitter = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                    __fmt__
                )
            indiv_output, combined_output = format_output(ts_type, in_twitter, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_twitter = indiv_output = combined_output = ""
    return in_twitter, indiv_output, combined_output, reason, tz_out


def to_twitter(dt_obj):
    """Convert a date/time value to a Twitter value"""
    ts_type, _, _, _ = ts_types["twitter"]
    try:
        unix_ts = (dt_obj.timestamp() * 1000) - 1288834974657
        out_twitter = str(int(unix_ts) << 22)
        ts_output, _ = format_output(ts_type, out_twitter)
    except Exception:
        handle(sys.exc_info())
        out_twitter = ts_output = ""
    return out_twitter, ts_output


def from_discord(timestamp):
    """Convert a Discord URL value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["discord"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_discord = indiv_output = combined_output = ""
        else:
            unix_ts = ((int(timestamp) >> 22) + 1420070400000) / 1000
            if unix_ts >= 32536799999:
                in_discord = indiv_output = combined_output = ""
            else:
                in_discord = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                    __fmt__
                )
            indiv_output, combined_output = format_output(ts_type, in_discord, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_discord = indiv_output = combined_output = ""
    return in_discord, indiv_output, combined_output, reason, tz_out


def to_discord(dt_obj):
    """Convert a date/time to a Discord URL value"""
    ts_type, _, _, _ = ts_types["discord"]
    try:
        timestamp = int(dt_obj.timestamp() * 1000) - 1420070400000
        out_discord = str(timestamp << 22)
        ts_output, _ = format_output(ts_type, out_discord)
    except Exception:
        handle(sys.exc_info())
        out_discord = ts_output = ""
    return out_discord, ts_output


def from_ksalnum(timestamp):
    """Extract a timestamp from a KSUID alpha-numeric value"""
    ts_type, reason, _, tz_out = ts_types["ksalnum"]
    try:
        if len(str(timestamp)) != 27 or not all(
            char in KSALNUM_CHARS for char in timestamp
        ):
            in_ksalnum = indiv_output = combined_output = ""
        else:
            length, i, variation = len(timestamp), 0, 0
            b_array = bytearray()
            for val in timestamp:
                variation += KSALNUM_CHARS.index(val) * (62 ** (length - (i + 1)))
                i += 1
            while variation > 0:
                b_array.append(variation & 0xFF)
                variation //= 256
            b_array.reverse()
            ts_bytes = bytes(b_array)[0:4]
            unix_ts = int.from_bytes(ts_bytes, "big", signed=False) + epochs["kstime"]
            in_ksalnum = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(ts_type, in_ksalnum, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ksalnum = indiv_output = combined_output = ""
    return in_ksalnum, indiv_output, combined_output, reason, tz_out


def to_ksalnum(dt_obj):
    """Convert a date/time to a KSUID alpha-numeric value"""
    ts_type, _, _, _ = ts_types["ksalnum"]
    try:
        out_ksalnum = ""
        unix_ts = int(dt_obj.timestamp())
        ts_bytes = (unix_ts - epochs["kstime"]).to_bytes(4, "big")
        filler = os.urandom(16)
        all_bytes = ts_bytes + filler
        big_int = int.from_bytes(all_bytes, "big")
        while big_int > 0:
            big_int, rem = divmod(big_int, 62)
            out_ksalnum = KSALNUM_CHARS[rem] + out_ksalnum
        out_ksalnum = out_ksalnum.rjust(27, "0")
        ts_output, _ = format_output(ts_type, out_ksalnum)
    except Exception:
        handle(sys.exc_info())
        out_ksalnum = ts_output = ""
    return out_ksalnum, ts_output


def from_mastodon(timestamp):
    """Convert a Mastodon value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["mastodon"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_mastodon = indiv_output = combined_output = ""
        else:
            ts_conversion = int(timestamp) >> 16
            unix_ts = float(ts_conversion) / 1000.0
            if int(unix_ts) >= 32536799999:
                in_mastodon = indiv_output = combined_output = ""
            else:
                in_mastodon = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_mastodon, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_mastodon = indiv_output = combined_output = ""
    return in_mastodon, indiv_output, combined_output, reason, tz_out


def to_mastodon(dt_obj):
    """Convert a date/time to a Mastodon value"""
    ts_type, _, _, _ = ts_types["mastodon"]
    try:
        unix_seconds = int((dt_obj - epochs[1970]).total_seconds()) * 1000
        bit_shift = unix_seconds << 16
        out_mastodon = f"{str(bit_shift)}"
        ts_output, _ = format_output(ts_type, out_mastodon)
    except Exception:
        handle(sys.exc_info())
        out_mastodon = ts_output = ""
    return out_mastodon, ts_output


def from_metasploit(timestamp):
    """Convert a Metasploit Payload UUID value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["metasploit"]
    meta_format = "8sBBBBBBBB"
    try:
        if len(str(timestamp)) < 22 or not all(
            char in URLSAFE_CHARS for char in timestamp
        ):
            in_metasploit = indiv_output = combined_output = ""
        else:
            b64decoded = base64.urlsafe_b64decode(timestamp[0:22] + "==")
            if len(b64decoded) < struct.calcsize(meta_format):
                in_metasploit = indiv_output = combined_output = ""
                return in_metasploit, indiv_output, combined_output, reason, tz_out
            (
                _,
                xor1,
                xor2,
                _,
                _,
                ts1_xored,
                ts2_xored,
                ts3_xored,
                ts4_xored,
            ) = struct.unpack(meta_format, b64decoded)
            unix_ts = struct.unpack(
                ">I",
                bytes(
                    [
                        ts1_xored ^ xor1,
                        ts2_xored ^ xor2,
                        ts3_xored ^ xor1,
                        ts4_xored ^ xor2,
                    ]
                ),
            )[0]
            in_metasploit = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(
                ts_type, in_metasploit, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_metasploit = indiv_output = combined_output = ""
    return in_metasploit, indiv_output, combined_output, reason, tz_out


def from_sony(timestamp):
    """Convert a Sonyflake value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["sony"]
    try:
        if len(str(timestamp)) != 15 or not all(
            char in hexdigits for char in timestamp
        ):
            in_sony = indiv_output = combined_output = ""
        else:
            dec_value = int(timestamp, 16)
            ts_value = dec_value >> 24
            unix_ts = (ts_value + 140952960000) * 10
            in_sony = dt.fromtimestamp(float(unix_ts) / 1000.0, timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(ts_type, in_sony, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_sony = indiv_output = combined_output = ""
    return in_sony, indiv_output, combined_output, reason, tz_out


def to_sony(dt_obj):
    """Convert a date/time to a Sonyflake value"""
    ts_type, _, _, _ = ts_types["sony"]
    try:
        dec_value = int((dt_obj.timestamp() * 100) - 140952960000)
        out_sony = f"{(dec_value << 24):0x}"
        ts_output, _ = format_output(ts_type, out_sony)
    except Exception:
        handle(sys.exc_info())
        out_sony = ts_output = ""
    return out_sony, ts_output


def from_uuid(timestamp):
    """Convert a UUID value to date/time"""
    ts_type, reason, _, tz_out = ts_types["uuid"]
    try:
        uuid_lower = timestamp.lower()
        uuid_regex = re.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        if not bool(uuid_regex.match(uuid_lower)):
            in_uuid = indiv_output = combined_output = ""
        else:
            u_data = uuid.UUID(uuid_lower)
            if u_data.version == 1:
                unix_ts = int((u_data.time / 10000) - 12219292800000)
                in_uuid = dt.fromtimestamp(
                    float(unix_ts) / 1000.0, timezone.utc
                ).strftime(__fmt__)
                indiv_output, combined_output = format_output(ts_type, in_uuid, tz_out)
            else:
                in_uuid = indiv_output = combined_output = ""
    except Exception:
        handle(sys.exc_info())
        in_uuid = indiv_output = combined_output = ""
    return in_uuid, indiv_output, combined_output, reason, tz_out


def to_uuid(dt_obj):
    """Convert a date/time value to a UUID"""
    ts_type, _, _, _ = ts_types["uuid"]
    try:
        timestamp = int((dt_obj - epochs[1582]).total_seconds() * 1e7)
        time_lo = timestamp & 0xFFFFFFFF
        time_mid = (timestamp >> 32) & 0xFFFF
        time_hi = (timestamp >> 48) & 0x0FFF
        time_hi_ver_1 = time_hi | (1 << 12)
        clock_seq = uuid.getnode() & 0x3FFF
        clock_seq_hi_variant = (clock_seq >> 8) | 0x80
        clock_seq_low = clock_seq & 0xFF
        node = uuid.getnode()
        out_uuid = str(
            uuid.UUID(
                fields=(
                    time_lo,
                    time_mid,
                    time_hi_ver_1,
                    clock_seq_hi_variant,
                    clock_seq_low,
                    node,
                )
            )
        )
        ts_output, _ = format_output(ts_type, out_uuid)
    except Exception:
        handle(sys.exc_info())
        out_uuid = ts_output = ""
    return out_uuid, ts_output


def from_dhcp6(timestamp):
    """Convert a DHCPv6 DUID value to date/time"""
    ts_type, reason, _, tz_out = ts_types["dhcp6"]
    try:
        if len(str(timestamp)) < 28 or not all(char in hexdigits for char in timestamp):
            in_dhcp6 = indiv_output = combined_output = ""
        else:
            dhcp6_bytes = timestamp[8:16]
            dhcp6_dec = int(dhcp6_bytes, 16)
            dhcp6_ts = epochs[2000] + timedelta(seconds=int(dhcp6_dec))
            in_dhcp6 = dhcp6_ts.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_dhcp6, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_dhcp6 = indiv_output = combined_output = ""
    return in_dhcp6, indiv_output, combined_output, reason, tz_out


def to_dhcp6(dt_obj):
    """Convert a timestamp to a DHCP DUID value"""
    ts_type, _, _, _ = ts_types["dhcp6"]
    try:
        unix_time = int((dt_obj - epochs[2000]).total_seconds())
        if int(unix_time) < 0:
            out_dhcp6 = "[!] Timestamp Boundary Exceeded [!]"
        else:
            dhcp6_ts = str(struct.pack(">L", unix_time).hex())
            out_dhcp6 = f"00010001{dhcp6_ts}000000000000"
        ts_output, _ = format_output(ts_type, out_dhcp6)
    except Exception:
        handle(sys.exc_info())
        out_dhcp6 = ts_output = ""
    return out_dhcp6, ts_output


def from_dotnet(timestamp):
    """Convert a .NET DateTime Ticks value to date/time"""
    ts_type, reason, _, tz_out = ts_types["dotnet"]
    try:
        if len(str(timestamp)) != 18 or not (timestamp).isdigit():
            in_dotnet = indiv_output = combined_output = ""
        else:
            dotnet_to_umil = (int(timestamp) - epochs["ticks"]) / epochs[
                "hundreds_nano"
            ]
            if dotnet_to_umil < 0:
                in_dotnet = indiv_output = combined_output = ""
            else:
                in_dotnet = dt.fromtimestamp(dotnet_to_umil, timezone.utc).strftime(
                    __fmt__
                )
            indiv_output, combined_output = format_output(ts_type, in_dotnet, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_dotnet = indiv_output = combined_output = ""
    return in_dotnet, indiv_output, combined_output, reason, tz_out


def to_dotnet(dt_obj):
    """Convert date to a .NET DateTime Ticks value"""
    ts_type, _, _, _ = ts_types["dotnet"]
    try:
        ts = dt_obj.timestamp() * epochs["hundreds_nano"]
        out_dotnet = str(int(ts + epochs["ticks"]))
        ts_output, _ = format_output(ts_type, out_dotnet)
    except Exception:
        handle(sys.exc_info())
        out_dotnet = ts_output = ""
    return out_dotnet, ts_output


def from_gbound(timestamp):
    """Convert a GMail Boundary value to date/time"""
    ts_type, reason, _, tz_out = ts_types["gbound"]
    try:
        if len(str(timestamp)) != 28 or not all(
            char in hexdigits for char in timestamp
        ):
            in_gbound = indiv_output = combined_output = ""
        else:
            working_value = timestamp[12:26]
            end = working_value[:6]
            begin = working_value[6:14]
            full_dec = int("".join(begin + end), 16)
            in_gbound = dt.fromtimestamp(full_dec / 1000000, timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(ts_type, in_gbound, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_gbound = indiv_output = combined_output = ""
    return in_gbound, indiv_output, combined_output, reason, tz_out


def to_gbound(dt_obj):
    """Convert date to a GMail Boundary value"""
    ts_type, _, _, _ = ts_types["gbound"]
    try:
        to_int = int(((dt_obj - epochs[1970]).total_seconds()) * 1000000)
        if len(f"{to_int:x}") < 14:
            to_int = f"0{to_int:x}"
        begin = to_int[8:]
        end = to_int[:8]
        out_gbound = f"000000000000{begin}{end}00"
        ts_output, _ = format_output(ts_type, out_gbound)
    except Exception:
        handle(sys.exc_info())
        out_gbound = ts_output = ""
    return out_gbound, ts_output


def from_gmsgid(timestamp):
    """Convert a GMail Message ID to a date/time value"""
    ts_type, reason, _, tz_out = ts_types["gmsgid"]
    try:
        gmsgid = timestamp
        if str(gmsgid).isdigit() and len(str(gmsgid)) == 19:
            gmsgid = str(f"{int(gmsgid):x}")
        if len(str(gmsgid)) != 16 or not all(char in hexdigits for char in gmsgid):
            in_gmsgid = indiv_output = combined_output = ""
        else:
            working_value = gmsgid[:11]
            to_int = int(working_value, 16)
            in_gmsgid = dt.fromtimestamp(to_int / 1000, timezone.utc).strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_gmsgid, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_gmsgid = indiv_output = combined_output = ""
    return in_gmsgid, indiv_output, combined_output, reason, tz_out


def to_gmsgid(dt_obj):
    """Convert date to a GMail Message ID value"""
    ts_type, _, _, _ = ts_types["gmsgid"]
    try:
        to_int = int(((dt_obj - epochs[1970]).total_seconds()) * 1000)
        ts_hex = f"{to_int:x}"
        out_gmsgid = f"{ts_hex}00000"
        ts_output, _ = format_output(ts_type, out_gmsgid)
    except Exception:
        handle(sys.exc_info())
        out_gmsgid = ts_output = ""
    return out_gmsgid, ts_output


def from_moto(timestamp):
    """Convert a Motorola 6-byte hex timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["moto"]
    try:
        if len(str(timestamp)) != 12 or not all(
            char in hexdigits for char in timestamp
        ):
            in_moto = indiv_output = combined_output = ""
        else:
            hex_to_dec = [
                int(timestamp[i : i + 2], 16) for i in range(0, len(timestamp), 2)
            ]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            if hex_to_dec[1] not in range(1, 13):
                in_moto = indiv_output = combined_output = ""
            else:
                try:
                    dt_obj = dt(
                        hex_to_dec[0],
                        hex_to_dec[1],
                        hex_to_dec[2],
                        hex_to_dec[3],
                        hex_to_dec[4],
                        hex_to_dec[5],
                    )
                except ValueError:
                    in_moto = indiv_output = combined_output = ""
                    return in_moto, indiv_output, combined_output, reason, tz_out
                in_moto = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_moto, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_moto = indiv_output = combined_output = ""
    return in_moto, indiv_output, combined_output, reason, tz_out


def to_moto(dt_obj):
    """Convert a date to Motorola's 6-byte hex timestamp"""
    ts_type, _, _, _ = ts_types["moto"]
    try:
        moto_year = f"{(dt_obj.year - 1970):02x}"
        moto_month = f"{(dt_obj.month):02x}"
        moto_day = f"{(dt_obj.day):02x}"
        moto_hour = f"{(dt_obj.hour):02x}"
        moto_minute = f"{(dt_obj.minute):02x}"
        moto_second = f"{(dt_obj.second):02x}"
        out_moto = str(
            f"{moto_year}{moto_month}{moto_day}"
            f"{moto_hour}{moto_minute}{moto_second}"
        )
        ts_output, _ = format_output(ts_type, out_moto)
    except Exception:
        handle(sys.exc_info())
        out_moto = ts_output = ""
    return out_moto, ts_output


def from_nokia(timestamp):
    """Convert a Nokia 4-byte value to date/time"""
    ts_type, reason, _, tz_out = ts_types["nokia"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_nokia = indiv_output = combined_output = ""
        else:
            to_int = int(timestamp, 16)
            int_diff = to_int ^ 4294967295
            int_diff = ~int_diff + 1
            unix_ts = int_diff + (epochs[2050] - epochs[1970]).total_seconds()
            if unix_ts < 0:
                in_nokia = indiv_output = combined_output = ""
            else:
                in_nokia = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output, combined_output = format_output(ts_type, in_nokia, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_nokia = indiv_output = combined_output = ""
    return in_nokia, indiv_output, combined_output, reason, tz_out


def to_nokia(dt_obj):
    """Convert a date/time value to a Nokia 4-byte timestamp"""
    ts_type, _, _, _ = ts_types["nokia"]
    try:
        unix_ts = (dt_obj - epochs[1970]).total_seconds()
        int_diff = int(unix_ts - (epochs[2050] - epochs[1970]).total_seconds())
        int_diff = int_diff - 1
        dec_value = ~int_diff ^ 4294967295
        out_nokia = f"{dec_value:x}"
        ts_output, _ = format_output(ts_type, out_nokia)
    except Exception:
        handle(sys.exc_info())
        out_nokia = ts_output = ""
    return out_nokia, ts_output


def from_nokiale(timestamp):
    """Convert a little-endian Nokia 4-byte value to date/time"""
    ts_type, reason, _, tz_out = ts_types["nokiale"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_nokiale = indiv_output = combined_output = ""
        else:
            to_be = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            to_int = int(to_be, 16)
            int_diff = to_int ^ 4294967295
            int_diff = ~int_diff + 1
            unix_ts = int_diff + (epochs[2050] - epochs[1970]).total_seconds()
            if unix_ts < 0:
                in_nokiale = indiv_output = combined_output = ""
            else:
                in_nokiale = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_nokiale, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_nokiale = indiv_output = combined_output = ""
    return in_nokiale, indiv_output, combined_output, reason, tz_out


def to_nokiale(dt_obj):
    """Convert a date/time value to a little-endian Nokia 4-byte timestamp"""
    ts_type, _, _, _ = ts_types["nokiale"]
    try:
        unix_ts = (dt_obj - epochs[1970]).total_seconds()
        int_diff = int(unix_ts - (epochs[2050] - epochs[1970]).total_seconds())
        int_diff = int_diff - 1
        dec_val = ~int_diff ^ 4294967295
        hex_val = f"{dec_val:x}"
        out_nokiale = "".join(
            [hex_val[i : i + 2] for i in range(0, len(hex_val), 2)][::-1]
        )
        ts_output, _ = format_output(ts_type, out_nokiale)
    except Exception:
        handle(sys.exc_info())
        out_nokiale = ts_output = ""
    return out_nokiale, ts_output


def from_ns40(timestamp):
    """Convert a Nokia S40 7-byte value to a time/time"""
    ts_type, reason, _, tz_out = ts_types["ns40"]
    try:
        if not len(timestamp) == 14 or not all(char in hexdigits for char in timestamp):
            in_ns40 = indiv_output = combined_output = ""
        else:
            ns40 = timestamp
            ns40_val = {
                "yr": ns40[:4],
                "mon": ns40[4:6],
                "day": ns40[6:8],
                "hr": ns40[8:10],
                "min": ns40[10:12],
                "sec": ns40[12:],
            }
            for each_key, _ in ns40_val.items():
                ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
            if ns40_val["yr"] > 9999:
                in_ns40 = indiv_output = combined_output = ""
            elif (int(ns40_val["mon"]) > 12) or (int(ns40_val["mon"] < 1)):
                in_ns40 = indiv_output = combined_output = ""
            else:
                in_ns40 = dt(
                    ns40_val["yr"],
                    ns40_val["mon"],
                    ns40_val["day"],
                    ns40_val["hr"],
                    ns40_val["min"],
                    ns40_val["sec"],
                ).strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_ns40, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ns40 = indiv_output = combined_output = ""
    return in_ns40, indiv_output, combined_output, reason, tz_out


def to_ns40(dt_obj):
    """Convert a date/time value to a Nokia S40 7-byte timestamp"""
    ts_type, _, _, _ = ts_types["ns40"]
    try:
        hex_vals = []
        hex_vals.append(f"{dt_obj.year:x}".zfill(4))
        hex_vals.append(f"{dt_obj.month:x}".zfill(2))
        hex_vals.append(f"{dt_obj.day:x}".zfill(2))
        hex_vals.append(f"{dt_obj.hour:x}".zfill(2))
        hex_vals.append(f"{dt_obj.minute:x}".zfill(2))
        hex_vals.append(f"{dt_obj.second:x}".zfill(2))
        out_ns40 = "".join(hex_vals)
        ts_output, _ = format_output(ts_type, out_ns40)
    except Exception:
        handle(sys.exc_info())
        out_ns40 = ts_output = ""
    return out_ns40, ts_output


def from_ns40le(timestamp):
    """Convert a little-endian Nokia S40 7-byte value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["ns40le"]
    try:
        if len(str(timestamp)) != 14 or not all(
            char in hexdigits for char in timestamp
        ):
            in_ns40le = indiv_output = combined_output = ""
        else:
            ns40le = timestamp
            ns40_val = {
                "yr": "".join(
                    [ns40le[i : i + 2] for i in range(0, len(ns40le[:4]), 2)][::-1]
                ),
                "mon": ns40le[4:6],
                "day": ns40le[6:8],
                "hr": ns40le[8:10],
                "min": ns40le[10:12],
                "sec": ns40le[12:],
            }
            for each_key, _ in ns40_val.items():
                ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
            if ns40_val["yr"] > 9999:
                in_ns40le = indiv_output = combined_output = ""
            elif (int(ns40_val["mon"]) > 12) or (int(ns40_val["mon"] < 1)):
                in_ns40le = indiv_output = combined_output = ""
            else:
                in_ns40le = dt(
                    ns40_val["yr"],
                    ns40_val["mon"],
                    ns40_val["day"],
                    ns40_val["hr"],
                    ns40_val["min"],
                    ns40_val["sec"],
                ).strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_ns40le, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ns40le = indiv_output = combined_output = ""
    return in_ns40le, indiv_output, combined_output, reason, tz_out


def to_ns40le(dt_obj):
    """Convert a date/time value to a little-endian Nokia S40 7-byte timestamp"""
    ts_type, _, _, _ = ts_types["ns40le"]
    try:
        hex_vals = []
        year_le = f"{dt_obj.year:x}".zfill(4)
        year_le = "".join(
            [year_le[i : i + 2] for i in range(0, len(year_le[:4]), 2)][::-1]
        )
        hex_vals.append(f"{year_le}".zfill(4))
        hex_vals.append(f"{dt_obj.month:x}".zfill(2))
        hex_vals.append(f"{dt_obj.day:x}".zfill(2))
        hex_vals.append(f"{dt_obj.hour:x}".zfill(2))
        hex_vals.append(f"{dt_obj.minute:x}".zfill(2))
        hex_vals.append(f"{dt_obj.second:x}".zfill(2))
        out_ns40le = "".join(hex_vals)
        ts_output, _ = format_output(ts_type, out_ns40le)
    except Exception:
        handle(sys.exc_info())
        out_ns40le = ts_output = ""
    return out_ns40le, ts_output


def from_bitdec(timestamp):
    """Convert a 10-digit Bitwise Decimal value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["bitdec"]
    try:
        if len(str(timestamp)) != 10 or not (timestamp).isdigit():
            in_bitdec = indiv_output = combined_output = ""
        else:
            full_ts = int(timestamp)
            bd_yr = full_ts >> 20
            bd_mon = (full_ts >> 16) & 15
            bd_day = (full_ts >> 11) & 31
            bd_hr = (full_ts >> 6) & 31
            bd_min = full_ts & 63
            try:
                in_bitdec = dt(bd_yr, bd_mon, bd_day, bd_hr, bd_min).strftime(__fmt__)
            except ValueError:
                in_bitdec = indiv_output = combined_output = ""
                return in_bitdec, indiv_output, combined_output, reason, tz_out
            indiv_output, combined_output = format_output(ts_type, in_bitdec, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_bitdec = indiv_output = combined_output = ""
    return in_bitdec, indiv_output, combined_output, reason, tz_out


def to_bitdec(dt_obj):
    """Convert a date/time value to a Bitwise Decimal timestamp"""
    ts_type, _, _, _ = ts_types["bitdec"]
    try:
        out_bitdec = str(
            (dt_obj.year << 20)
            + (dt_obj.month << 16)
            + (dt_obj.day << 11)
            + (dt_obj.hour << 6)
            + (dt_obj.minute)
        )
        ts_output, _ = format_output(ts_type, out_bitdec)
    except Exception:
        handle(sys.exc_info())
        out_bitdec = ts_output = ""
    return out_bitdec, ts_output


def from_bitdate(timestamp):
    """Convert a Samsung/LG 4-byte hex timestamp to a date/time"""
    ts_type, reason, _, tz_out = ts_types["bitdate"]
    try:
        if len(str(timestamp)) != 8 or not all(char in hexdigits for char in timestamp):
            in_bitdate = indiv_output = combined_output = ""
        else:
            to_le = "".join(
                [timestamp[i : i + 2] for i in range(0, len(str(timestamp)), 2)][::-1]
            )
            to_binary = f"{int(to_le, 16):032b}"
            bitdate_yr = int(to_binary[:12], 2)
            bitdate_mon = int(to_binary[12:16], 2)
            bitdate_day = int(to_binary[16:21], 2)
            bitdate_hr = int(to_binary[21:26], 2)
            bitdate_min = int(to_binary[26:32], 2)
            if bitdate_yr not in range(1900, 2500):
                in_bitdate = indiv_output = combined_output = ""
                return in_bitdate, indiv_output, combined_output, reason, tz_out
            try:
                in_bitdate = dt(
                    bitdate_yr, bitdate_mon, bitdate_day, bitdate_hr, bitdate_min
                ).strftime(__fmt__)
            except ValueError:
                in_bitdate = indiv_output = combined_output = ""
                return in_bitdate, indiv_output, combined_output, reason, tz_out
            indiv_output, combined_output = format_output(ts_type, in_bitdate, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_bitdate = indiv_output = combined_output = ""
    return in_bitdate, indiv_output, combined_output, reason, tz_out


def to_bitdate(dt_obj):
    """Convert a date/time value to a Samsung/LG timestamp"""
    ts_type, _, _, _ = ts_types["bitdate"]
    try:
        bitdate_yr = f"{dt_obj.year:012b}"
        bitdate_mon = f"{dt_obj.month:04b}"
        bitdate_day = f"{dt_obj.day:05b}"
        bitdate_hr = f"{dt_obj.hour:05b}"
        bitdate_min = f"{dt_obj.minute:06b}"
        to_hex = str(
            struct.pack(
                ">I",
                int(
                    bitdate_yr + bitdate_mon + bitdate_day + bitdate_hr + bitdate_min, 2
                ),
            ).hex()
        )
        out_bitdate = "".join(
            [to_hex[i : i + 2] for i in range(0, len(to_hex), 2)][::-1]
        )
        ts_output, _ = format_output(ts_type, out_bitdate)
    except Exception:
        handle(sys.exc_info())
        out_bitdate = ts_output = ""
    return out_bitdate, ts_output


def from_ksdec(timestamp):
    """Convert a KSUID decimal value to a date"""
    ts_type, reason, _, tz_out = ts_types["ksdec"]
    try:
        if len(timestamp) != 9 or not timestamp.isdigit():
            in_ksdec = indiv_output = combined_output = ""
        else:
            ts_val = int(timestamp) + int(epochs["kstime"])
            in_ksdec = dt.fromtimestamp(float(ts_val), timezone.utc).strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_ksdec, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ksdec = indiv_output = combined_output = ""
    return in_ksdec, indiv_output, combined_output, reason, tz_out


def to_ksdec(dt_obj):
    """Convert date to a KSUID decimal value"""
    ts_type, _, _, _ = ts_types["ksdec"]
    try:
        unix_ts = str(int((dt_obj - epochs[1970]).total_seconds()))
        out_ksdec = str(int(unix_ts) - int(epochs["kstime"]))
        if int(out_ksdec) < 0:
            out_ksdec = "[!] Timestamp Boundary Exceeded [!]"
        ts_output, _ = format_output(ts_type, out_ksdec)
    except Exception:
        handle(sys.exc_info())
        out_ksdec = ts_output = ""
    return out_ksdec, ts_output


def from_biomehex(timestamp):
    """Convert an Apple Biome Hex value to a date - from Little Endian"""
    ts_type, reason, _, tz_out = ts_types["biomehex"]
    try:
        biomehex = str(timestamp)
        if len(biomehex) != 16 or not all(char in hexdigits for char in biomehex):
            in_biomehex = indiv_output = combined_output = ""
        else:
            if biomehex[:2] == "41":
                biomehex = "".join(
                    [biomehex[i : i + 2] for i in range(0, len(biomehex), 2)][::-1]
                )
            byte_val = bytes.fromhex(str(biomehex))
            nsdate_val = struct.unpack("<d", byte_val)[0]
            if nsdate_val >= 1e17:
                in_biomehex = indiv_output = combined_output = ""
            else:
                dt_obj = epochs[2001] + timedelta(seconds=float(nsdate_val))
                in_biomehex = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_biomehex, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_biomehex = indiv_output = combined_output = ""
    return in_biomehex, indiv_output, combined_output, reason, tz_out


def to_biomehex(dt_obj):
    """Convert a date/time to an Apple Biome Hex value"""
    ts_type, _, _, _ = ts_types["biomehex"]
    try:
        bplist_stamp = str(float((dt_obj - epochs[2001]).total_seconds()))
        byte_biome = struct.pack(">d", float(bplist_stamp))
        out_biomehex = bytes.hex(byte_biome)
        ts_output, _ = format_output(ts_type, out_biomehex)
    except Exception:
        handle(sys.exc_info())
        out_biomehex = ts_output = ""
    return out_biomehex, ts_output


def from_biome64(timestamp):
    """Convert a 64-bit decimal value to a date/time value"""
    ts_type, reason, _, tz_out = ts_types["biome64"]
    try:
        if len(timestamp) != 19 or not timestamp.isdigit():
            in_biome64 = indiv_output = combined_output = ""
        else:
            nsdate_unpacked = int(
                struct.unpack("<d", int(timestamp).to_bytes(8, "little"))[0]
            )
            if nsdate_unpacked >= 1e17:
                in_biome64 = indiv_output = combined_output = ""
            else:
                dt_obj = epochs[2001] + timedelta(seconds=float(nsdate_unpacked))
                in_biome64 = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_biome64, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_biome64 = indiv_output = combined_output = ""
    return in_biome64, indiv_output, combined_output, reason, tz_out


def to_biome64(dt_obj):
    """Convert a date/time value to a"""
    ts_type, _, _, _ = ts_types["biome64"]
    try:
        nsdate_stamp = float((dt_obj - epochs[2001]).total_seconds())
        out_biome64 = str(int.from_bytes(struct.pack(">d", nsdate_stamp), "big"))
        ts_output, _ = format_output(ts_type, out_biome64)
    except Exception:
        handle(sys.exc_info())
        out_biome64 = ts_output = ""
    return out_biome64, ts_output


def from_s32(timestamp):
    """
    Convert an S32 timestamp to a date/time value
    """
    ts_type, reason, _, tz_out = ts_types["s32"]
    try:
        result = 0
        timestamp = str(timestamp)
        if len(timestamp) != 9 or not all(char in S32_CHARS for char in timestamp):
            in_s32 = indiv_output = combined_output = ""
        else:
            for char in timestamp:
                result = result * 32 + S32_CHARS.index(char)
            dt_obj = dt.fromtimestamp(result / 1000.0, timezone.utc)
            in_s32 = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_s32, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_s32 = indiv_output = combined_output = ""
    return in_s32, indiv_output, combined_output, reason, tz_out


def to_s32(dt_obj):
    """Convert a date/time to an S32-encoded timestamp"""
    ts_type, _, _, _ = ts_types["s32"]
    try:
        result = ""
        index = 0
        unix_mil = int(((dt_obj - epochs[1970]).total_seconds())) * 1000
        while unix_mil:
            index = unix_mil % 32
            unix_mil = math.floor(unix_mil / 32)
            result = S32_CHARS[index] + result
        out_s32 = result
        ts_output, _ = format_output(ts_type, out_s32)
    except Exception:
        handle(sys.exc_info())
        out_s32 = ts_output = ""
    return out_s32, ts_output


def from_apache(timestamp):
    """
    Convert an Apache hex timestamp to a date/time value
    This value has 13 hex characters, and does not fit a byte boundary
    """
    ts_type, reason, _, tz_out = ts_types["apache"]
    try:
        timestamp = str(timestamp)
        if len(timestamp) != 13 or not all(char in hexdigits for char in timestamp):
            in_apache = indiv_output = combined_output = ""
        else:
            dec_val = int(timestamp, 16)
            dt_obj = epochs[1970] + timedelta(microseconds=dec_val)
            in_apache = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_apache, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_apache = indiv_output = combined_output = ""
    return in_apache, indiv_output, combined_output, reason, tz_out


def to_apache(dt_obj):
    """Convert a date/time to an Apache cookie value"""
    ts_type, _, _, _ = ts_types["apache"]
    try:
        apache_int = int(((dt_obj - epochs[1970]).total_seconds()) * 1000000)
        out_apache = f"{apache_int:x}"
        ts_output, _ = format_output(ts_type, out_apache)
    except Exception:
        handle(sys.exc_info())
        out_apache = ts_output = ""
    return out_apache, ts_output


def from_leb128hex(timestamp):
    """Convert a LEB 128 hex value to a date"""
    ts_type, reason, _, tz_out = ts_types["leb128hex"]
    try:
        if not len(timestamp) % 2 == 0 or not all(
            char in hexdigits for char in timestamp
        ):
            in_leb128_hex = indiv_output = combined_output = ""
        else:
            ts_hex_list = [(timestamp[i : i + 2]) for i in range(0, len(timestamp), 2)]
            unix_milli = 0
            shift = 0
            for hex_val in ts_hex_list:
                byte_val = int(hex_val, 16)
                unix_milli |= (byte_val & 0x7F) << shift
                if (byte_val & 0x80) == 0:
                    break
                shift += 7
            in_leb128_hex, _, _, _, _ = from_unixmilli(str(unix_milli))
            indiv_output, combined_output = format_output(
                ts_type, in_leb128_hex, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_leb128_hex = indiv_output = combined_output = ""
    return in_leb128_hex, indiv_output, combined_output, reason, tz_out


def to_leb128hex(dt_obj):
    """Convert a date to a LEB128 hex value."""
    ts_type, _, _, _ = ts_types["leb128hex"]
    try:
        unix_milli, _ = to_unixmilli(dt_obj)
        unix_milli = int(unix_milli)
        byte_list = []
        while True:
            byte_val = unix_milli & 0x7F
            unix_milli >>= 7
            if unix_milli != 0:
                byte_val |= 0x80
            byte_list.append(byte_val)
            if unix_milli == 0:
                break
        out_leb128_hex = "".join([f"{byte_val:02x}" for byte_val in byte_list])
        ts_output, _ = format_output(ts_type, out_leb128_hex)
    except Exception:
        handle(sys.exc_info())
        out_leb128_hex = ts_output = ""
    return out_leb128_hex, ts_output


def from_juliandec(timestamp):
    """Convert Julian Date decimal value to a date"""
    ts_type, reason, _, tz_out = ts_types["juliandec"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 7)
                and (len(timestamp.split(".")[1]) in range(0, 11))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_julian_dec = indiv_output = combined_output = ""
        else:
            try:
                timestamp = float(timestamp)
            except Exception:
                timestamp = int(timestamp)

            yr, mon, day, hr, mins, sec, mil = jd.to_gregorian(timestamp)
            dt_vals = [yr, mon, day, hr, mins, sec, mil]
            if any(val < 0 for val in dt_vals):
                in_julian_dec = indiv_output = combined_output = ""
            else:
                in_julian_dec = (dt(yr, mon, day, hr, mins, sec, mil)).strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_julian_dec, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_julian_dec = indiv_output = combined_output = ""
    return in_julian_dec, indiv_output, combined_output, reason, tz_out


def to_juliandec(dt_obj):
    """Convert a date to a Julian Date"""
    ts_type, _, _, _ = ts_types["juliandec"]
    try:
        out_julian_dec = str(
            jd.from_gregorian(
                dt_obj.year,
                dt_obj.month,
                dt_obj.day,
                dt_obj.hour,
                dt_obj.minute,
                dt_obj.second,
            )
        )
        ts_output, _ = format_output(ts_type, out_julian_dec)
    except Exception:
        handle(sys.exc_info())
        out_julian_dec = ts_output = ""
    return out_julian_dec, ts_output


def from_julianhex(timestamp):
    """Convert Julian Date hex value to a date"""
    ts_type, reason, _, tz_out = ts_types["julianhex"]
    try:
        if not len(timestamp) // 2 == 7 or not all(
            char in hexdigits for char in timestamp
        ):
            in_julian_hex = indiv_output = combined_output = ""
        else:
            julianday = int(timestamp[:6], 16)
            julianmil = int(timestamp[6:], 16)
            julianmil = julianmil / 10 ** int((len(str(julianmil))))
            julian_date = int(julianday) + int(julianmil)
            yr, mon, day, hr, mins, sec, mil = jd.to_gregorian(julian_date)
            dt_vals = [yr, mon, day, hr, mins, sec, mil]
            if yr > 3000 or any(val < 0 for val in dt_vals):
                in_julian_hex = indiv_output = combined_output = ""
            else:
                dt_obj = dt(yr, mon, day, hr, mins, sec, mil)
                in_julian_hex = dt_obj.strftime(__fmt__)
                indiv_output, combined_output = format_output(
                    ts_type, in_julian_hex, tz_out
                )
    except Exception:
        handle(sys.exc_info())
        in_julian_hex = indiv_output = combined_output = ""
    return in_julian_hex, indiv_output, combined_output, reason, tz_out


def to_julianhex(dt_obj):
    """Convert a date to a Julian Hex Date"""
    ts_type, _, _, _ = ts_types["julianhex"]
    try:
        jul_dec = jd.from_gregorian(
            dt_obj.year,
            dt_obj.month,
            dt_obj.day,
            dt_obj.hour,
            dt_obj.minute,
            dt_obj.second,
        )
        if isinstance(jul_dec, float):
            left_val, right_val = str(jul_dec).split(".")
            left_val = f"{int(left_val):06x}"
            right_val = f"{int(right_val):08x}"
        elif isinstance(jul_dec, int):
            left_val = f"{jul_dec:06x}"
            right_val = f"{0:08x}"
        out_julian_hex = f"{str(left_val)}{str(right_val)}"
        ts_output, _ = format_output(ts_type, out_julian_hex)
    except Exception:
        handle(sys.exc_info())
        out_julian_hex = ts_output = ""
    return out_julian_hex, ts_output


def from_semioctet(timestamp):
    """Convert from a Semi-Octet decimal value to a date"""
    ts_type, reason, _, tz_out = ts_types["semioctet"]
    try:
        yr = mon = day = hr = mins = sec = None
        if (
            len(str(timestamp)) != 12
            or len(str(timestamp)) != 14
            and not str(timestamp).isdigit()
        ):
            in_semi_octet = indiv_output = combined_output = ""
        else:
            if len(str(timestamp)) == 12:
                yr, mon, day, hr, mins, sec = [
                    (a + b)[::-1] for a, b in zip(timestamp[::2], timestamp[1::2])
                ]
            elif len(str(timestamp)) == 14:
                yr, mon, day, hr, mins, sec, _ = [
                    (a + b)[::-1] for a, b in zip(timestamp[::2], timestamp[1::2])
                ]
            try:
                dt_obj = dt(
                    int(yr) + 2000, int(mon), int(day), int(hr), int(mins), int(sec)
                )
            except ValueError:
                in_semi_octet = indiv_output = combined_output = ""
                return in_semi_octet, indiv_output, combined_output, reason, tz_out
            in_semi_octet = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(
                ts_type, in_semi_octet, tz_out
            )
    except Exception:
        handle(sys.exc_info())
        in_semi_octet = indiv_output = combined_output = ""
    return in_semi_octet, indiv_output, combined_output, reason, tz_out


def to_semioctet(dt_obj):
    """Convert a date to a Semi-Octet decimal value"""
    ts_type, _, _, _ = ts_types["semioctet"]
    try:
        swap_list = []
        ts_vals = [
            str(f"{(dt_obj.year - 2000):02d}"),
            str(f"{dt_obj.month:02d}"),
            str(f"{dt_obj.day:02d}"),
            str(f"{dt_obj.hour:02d}"),
            str(f"{dt_obj.minute:02d}"),
            str(f"{dt_obj.second:02d}"),
        ]
        for each in ts_vals:
            swap_list.append(each[::-1])
        out_semi_octet = "".join(swap_list)
        ts_output, _ = format_output(ts_type, out_semi_octet)
    except Exception:
        handle(sys.exc_info())
        out_semi_octet = ts_output = ""
    return out_semi_octet, ts_output


def from_ved(timestamp):
    """Convert from a VED urlsafe base64 encoded protobuf"""
    ts_type, reason, _, tz_out = ts_types["ved"]
    try:
        if not all(char in URLSAFE_CHARS for char in timestamp):
            in_ved = indiv_output = combined_output = ""
        else:
            decoded_ved = None
            if timestamp[0].isdigit() and int(timestamp[0]) in range(0, 3):
                timestamp = timestamp[1:]
            padding_check = len(timestamp) % 4
            if padding_check != 0:
                padding_reqd = 4 - padding_check
                result_ved = timestamp + (padding_reqd * "=")
            else:
                result_ved = timestamp
            try:
                decoded_ved = base64.urlsafe_b64decode(result_ved)
            except base64.binascii.Error:
                in_ved = indiv_output = combined_output = ""
            try:
                buff_content, _ = blackboxprotobuf.decode_message(decoded_ved)
            except (DecoderException, TypeError):
                in_ved = indiv_output = combined_output = ""
                return in_ved, indiv_output, combined_output, reason, tz_out
            if "13" in buff_content:
                ved_ts = buff_content["13"]["1"]["1"]
                in_ved = dt.fromtimestamp(ved_ts / 1000000, timezone.utc).strftime(
                    __fmt__
                )
                indiv_output, combined_output = format_output(ts_type, in_ved, tz_out)
            else:
                in_ved = indiv_output = combined_output = ""
    except Exception:
        handle(sys.exc_info())
        in_ved = indiv_output = combined_output = ""
    return in_ved, indiv_output, combined_output, reason, tz_out


def from_gclid(timestamp):
    """Convert from a gclid urlsafe base64 encoded protobuf"""
    ts_type, reason, _, tz_out = ts_types["gclid"]
    try:
        if not all(char in URLSAFE_CHARS for char in timestamp):
            in_gclid = indiv_output = combined_output = ""
        else:
            decoded_gclid = None
            if timestamp[0].isdigit() and int(timestamp[0]) in range(0, 3):
                timestamp = timestamp[1:]
            padding_check = len(timestamp) % 4
            if padding_check != 0:
                padding_reqd = 4 - padding_check
                result_gclid = timestamp + (padding_reqd * "=")
            else:
                result_gclid = timestamp
            try:
                decoded_gclid = base64.urlsafe_b64decode(result_gclid)
            except base64.binascii.Error:
                in_gclid = indiv_output = combined_output = ""
            try:
                buff_content, _ = blackboxprotobuf.decode_message(decoded_gclid)
            except (DecoderException, TypeError):
                in_gclid = indiv_output = combined_output = ""
                return in_gclid, indiv_output, combined_output, reason, tz_out
            if (
                "1" in buff_content
                and isinstance(buff_content["1"], int)
                and len(str(buff_content["1"])) == 16
            ):
                gclid_ts = buff_content["1"]
                in_gclid = dt.fromtimestamp(gclid_ts / 1000000, timezone.utc).strftime(
                    __fmt__
                )
                indiv_output, combined_output = format_output(ts_type, in_gclid, tz_out)
            else:
                in_gclid = indiv_output = combined_output = ""
    except Exception:
        handle(sys.exc_info())
        in_gclid = indiv_output = combined_output = ""
    return in_gclid, indiv_output, combined_output, reason, tz_out


def from_linkedin(timestamp):
    """Convert from a LinkedIn Post Activity ID"""
    ts_type, reason, _, tz_out = ts_types["linkedin"]
    try:
        if not str(timestamp).isdigit():
            in_linkedin = indiv_output = combined_output = ""
        else:
            bin_convert = bin(int(timestamp))[2:43]
            li_ts = int(bin_convert, 2) / 1000
            in_linkedin = dt.fromtimestamp(li_ts, timezone.utc).strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_linkedin, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_linkedin = indiv_output = combined_output = ""
    return in_linkedin, indiv_output, combined_output, reason, tz_out


def to_linkedin(dt_obj):
    """Convert a date/time to a LinkedIn Post Activity ID"""
    ts_type, _, _, _ = ts_types["linkedin"]
    padding = "1011100101100100110110"
    try:
        unix_ts = dt_obj.timestamp() * 1000
        to_bin = bin(int(unix_ts))[2:43]
        out_linkedin = str(int(to_bin + padding, 2))
        ts_output, _ = format_output(ts_type, out_linkedin)
    except Exception:
        handle(sys.exc_info())
        out_linkedin = ts_output = ""
    return out_linkedin, ts_output


def from_ulid(timestamp):
    """Convert from a ULID value"""
    ts_type, reason, _, tz_out = ts_types["ulid"]
    try:
        if (
            not all(char in BASE32_CHARS for char in timestamp)
            or len(str(timestamp)) != 26
        ):
            in_ulid = indiv_output = combined_output = ""
        else:
            ulid_dt = ULID.parse(timestamp).datetime
            in_ulid = ulid_dt.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_ulid, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_ulid = indiv_output = combined_output = ""
    return in_ulid, indiv_output, combined_output, reason, tz_out


def to_ulid(dt_obj):
    """Convert a date to a ULID value"""
    ts_type, _, _, _ = ts_types["ulid"]
    try:
        out_ulid = str(ULID.from_datetime(dt_obj))
        ts_output, _ = format_output(ts_type, out_ulid)
    except Exception:
        handle(sys.exc_info())
        out_ulid = ts_output = ""
    return out_ulid, ts_output


def from_dttm(timestamp):
    """Convert a Microsoft DTTM timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["dttm"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_dttm = indiv_output = combined_output = ""
        else:
            int_ts = int(timestamp, 16)
            binary = f"{int_ts:032b}"
            stamp = [
                binary[:3],
                binary[3:12],
                binary[12:16],
                binary[16:21],
                binary[21:26],
                binary[26:32],
            ]
            for binary in stamp[:]:
                dec = int(binary, 2)
                stamp.remove(binary)
                stamp.append(dec)
            dttm_dow = stamp[0]
            dttm_year = stamp[1] + 1900
            dttm_month = stamp[2]
            dttm_dom = stamp[3]
            dttm_hour = stamp[4]
            dttm_min = stamp[5]
            try:
                out_of_range = any(
                    not low <= value < high
                    for value, (low, high) in zip(
                        (
                            dttm_dow,
                            dttm_year,
                            dttm_month,
                            dttm_dom,
                            dttm_hour,
                            dttm_min,
                        ),
                        (
                            (0, 6),
                            (1900, 2050),
                            (1, 13),
                            (0, monthrange(dttm_year, dttm_month)[1] + 1),
                            (0, 24),
                            (0, 60),
                        ),
                    )
                )
                if out_of_range:
                    in_dttm = indiv_output = combined_output = ""
                    return in_dttm, indiv_output, combined_output, reason, tz_out
            except (IllegalMonthError, ValueError):
                in_dttm = indiv_output = combined_output = ""
                return in_dttm, indiv_output, combined_output, reason, tz_out
            dt_obj = dt(dttm_year, dttm_month, dttm_dom, dttm_hour, dttm_min, 0)
            in_dttm = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_dttm, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_dttm = indiv_output = combined_output = ""
    return in_dttm, indiv_output, combined_output, reason, tz_out


def to_dttm(dt_obj):
    """Convert a date to a Microsoft DTTM timestamp"""
    ts_type, _, _, _ = ts_types["dttm"]
    try:
        year = f"{(dt_obj.year - 1900):09b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        dow = f"{dt_obj.isoweekday():03b}"
        out_dttm = str(
            struct.pack(">I", int(dow + year + month + day + hour + minute, 2)).hex()
        )
        ts_output, _ = format_output(ts_type, out_dttm)
    except Exception:
        handle(sys.exc_info())
        out_dttm = ts_output = ""
    return out_dttm, ts_output


def from_bcd(timestamp):
    """Convert a Binary Coded Decimal timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["bcd"]
    try:
        if len(timestamp) != 12 and not timestamp.isdigit():
            in_bcd = indiv_output = combined_output = ""
        else:
            yr, mon, day, hr, mins, sec = [
                timestamp[i : i + 2] for i in range(0, len(timestamp), 2)
            ]
            yr, mon, day, hr, mins, sec = (
                int(yr) + 2000,
                int(mon),
                int(day),
                int(hr),
                int(mins),
                int(sec),
            )
            in_bcd = dt(yr, mon, day, hr, mins, sec, tzinfo=timezone.utc).strftime(
                __fmt__
            )
            indiv_output, combined_output = format_output(ts_type, in_bcd, tz_out)
    except ValueError:
        in_bcd = indiv_output = combined_output = ""
    except Exception:
        handle(sys.exc_info())
        in_bcd = indiv_output = combined_output = ""
    return in_bcd, indiv_output, combined_output, reason, tz_out


def to_bcd(dt_obj):
    """Convert a date/time to a Binary Coded Decimal"""
    ts_type, _, _, _ = ts_types["bcd"]
    try:
        yr, mon, day, hr, mins, sec = dt_obj.strftime("%Y-%m-%d-%H-%M-%S").split("-")
        yr = str(int(yr) - 2000)
        out_bcd = f"{yr}{mon}{day}{hr}{mins}{sec}"
        ts_output, _ = format_output(ts_type, out_bcd)
    except Exception:
        handle(sys.exc_info())
        out_bcd = ts_output = ""
    return out_bcd, ts_output


def from_dvr(timestamp):
    """Convert a DVR (WFS / DHFS) file system timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["dvr"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_dvr = indiv_output = combined_output = ""
        else:
            int_ts = int(timestamp, 16)
            binary = f"{int_ts:032b}"
            stamp = [
                binary[:6],
                binary[6:10],
                binary[10:15],
                binary[15:20],
                binary[20:26],
                binary[26:32],
            ]
            for binary in stamp[:]:
                dec = int(binary, 2)
                stamp.remove(binary)
                stamp.append(dec)
            dvr_yr = stamp[0] + 2000
            dvr_mon = stamp[1]
            dvr_day = stamp[2]
            dvr_hr = stamp[3]
            dvr_min = stamp[4]
            dvr_sec = stamp[5]
            try:
                out_of_range = any(
                    not low <= value < high
                    for value, (low, high) in zip(
                        (
                            dvr_yr,
                            dvr_mon,
                            dvr_day,
                            dvr_hr,
                            dvr_min,
                            dvr_sec,
                        ),
                        (
                            (2000, 3000),
                            (1, 13),
                            (0, monthrange(dvr_yr, dvr_mon)[1] + 1),
                            (0, 24),
                            (0, 60),
                            (0, 60),
                        ),
                    )
                )
                if out_of_range:
                    in_dvr = indiv_output = combined_output = ""
                    return in_dvr, indiv_output, combined_output, reason, tz_out
            except (IllegalMonthError, ValueError):
                in_dvr = indiv_output = combined_output = ""
                return in_dvr, indiv_output, combined_output, reason, tz_out
            dt_obj = dt(dvr_yr, dvr_mon, dvr_day, dvr_hr, dvr_min, dvr_sec)
            in_dvr = dt_obj.strftime(__fmt__)
            indiv_output, combined_output = format_output(ts_type, in_dvr, tz_out)
    except Exception:
        handle(sys.exc_info())
        in_dvr = indiv_output = combined_output = ""
    return in_dvr, indiv_output, combined_output, reason, tz_out


def to_dvr(dt_obj):
    """Convert a date to a DVR (WFS / DHFS) file system timestamp"""
    ts_type, _, _, _ = ts_types["dvr"]
    try:
        year = f"{(dt_obj.year - 2000):06b}"
        month = f"{dt_obj.month:04b}"
        day = f"{dt_obj.day:05b}"
        hour = f"{dt_obj.hour:05b}"
        minute = f"{dt_obj.minute:06b}"
        sec = f"{dt_obj.second:06b}"
        out_dvr = str(
            struct.pack(">I", int(year + month + day + hour + minute + sec, 2)).hex()
        )
        ts_output, _ = format_output(ts_type, out_dvr)
    except Exception:
        handle(sys.exc_info())
        out_dvr = ts_output = ""
    return out_dvr, ts_output


def date_range(start, end, check_date):
    """Check if date is in range of start and end, return True if it is"""
    if start <= end:
        return start <= check_date <= end
    return start <= check_date or check_date <= end


def from_all(timestamps):
    """Output all processed timestamp values and find date from provided timestamp"""
    this_yr = int(dt.now(timezone.utc).strftime("%Y"))
    full_list = {}
    for _, funcs in single_funcs.items():
        func = funcs[0]
        func_name = func.__name__.replace("from_", "")
        (result, _, combined_output, _, tz_out) = func(timestamps)
        if result and combined_output:
            if isinstance(result, str):
                if int(dt.fromisoformat(result).strftime("%Y")) not in range(
                    this_yr - 5, this_yr + 5
                ):
                    combined_output = combined_output.strip(__red__).strip(__clr__)
            full_list[func_name] = [result, combined_output, tz_out]
    return full_list


def to_timestamps(dt_obj):
    """Convert provided date to all timestamps"""
    results = {}
    ts_outputs = []
    if isinstance(dt_obj, str):
        try:
            dt_obj = dt.fromisoformat(dt_obj)
        except ValueError as exc:
            print(
                f"[!] Check that your input timestamp follows the format: 'YYYY-MM-DD HH:MM:SS'\n"
                f"[!] with '.ffffff' for milliseconds and '+/-HH:MM' for timezones:\n[!] {exc}"
            )
            sys.exit(1)
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    for _, funcs in single_funcs.items():
        func = funcs[1]
        if not func:
            continue
        result, ts_output = func(dt_obj)
        func_name = (func.__name__).replace("to_", "")
        if result and isinstance(result, str):
            results[func_name] = result
            ts_outputs.append(ts_output)
    return results, ts_outputs


def launch_gui():
    """Execute the application"""
    td_app = QApplication([__appname__, "windows:darkmode=2"])
    td_app.setApplicationDisplayName(__appname__)
    td_app.setApplicationName(__appname__)
    icon = QPixmap()
    icon.loadFromData(base64.b64decode(TimeDecodeGui.__fingerprint__))
    td_app.setWindowIcon(QIcon(icon))
    td_app.setStyle("Fusion")
    td_form = TimeDecodeGui()
    td_form.show()
    td_app.exec()


def handle(error):
    """Error handling output and formatting to include function causing error"""
    exc_type, exc_obj, _ = error
    error_tb = traceback.extract_stack()[:-3] + traceback.extract_tb(
        exc_obj.__traceback__
    )
    _, line_no, function_name, _ = error_tb[-1]
    print(f"{str(exc_type.__name__)}: {str(exc_obj)} - {function_name} line {line_no}")


def formats(display="ALL"):
    """Displays a PrettyTable output of examples of all timestamps and their formats"""
    structures = {}
    for arg, data_list in ts_types.items():
        structures[data_list[0]] = (data_list[1], data_list[2], arg)
    structures = sorted(structures.items(), key=lambda item: item[1][0].casefold())
    table = PrettyTable()
    table.set_style(TableStyle.SINGLE_BORDER)
    table.align = "l"
    table.field_names = ["Type", "Format", "Example", "Argument"]
    for structure in structures:
        ts_type, details = structure
        argument = f"--{details[2]}"
        if display == "ALL":
            table.add_row([ts_type, details[0], details[1], argument])
        elif details[2] == display:
            table.add_row([ts_type, details[0], details[1], argument])
    print(table)
    print("* BE = Big-Endian / LE = Little-Endian")


def format_output(ts_type, ts, tz=None):
    """Format the output of the timestamp functions"""
    tabs = ""
    if len(ts_type) < 15:
        tabs = "\t\t\t"
    elif len(ts_type) in range(15, 23):
        tabs = "\t\t"
    elif len(ts_type) in range(23, 32):
        tabs = "\t"
    if tz:
        indiv_output = f"{ts_type}: {ts} {tz}"
        combined_output = f"{__red__}{ts_type}:{tabs}{ts} {tz}{__clr__}"
    else:
        indiv_output = f"{ts_type}:{tabs}{ts}"
        combined_output = None
    return indiv_output, combined_output


single_funcs = {
    "active": [from_active, to_active],
    "apache": [from_apache, to_apache],
    "biome64": [from_biome64, to_biome64],
    "biomehex": [from_biomehex, to_biomehex],
    "mac": [from_mac, to_mac],
    "iostime": [from_iostime, to_iostime],
    "bplist": [from_bplist, to_bplist],
    "bcd": [from_bcd, to_bcd],
    "bitdate": [from_bitdate, to_bitdate],
    "bitdec": [from_bitdec, to_bitdec],
    "dhcp6": [from_dhcp6, to_dhcp6],
    "discord": [from_discord, to_discord],
    "dvr": [from_dvr, to_dvr],
    "exfat": [from_exfat, to_exfat],
    "fat": [from_fat, to_fat],
    "gbound": [from_gbound, to_gbound],
    "gmsgid": [from_gmsgid, to_gmsgid],
    "chrome": [from_chrome, to_chrome],
    "eitime": [from_eitime, to_eitime],
    "gclid": [from_gclid, None],
    "ved": [from_ved, None],
    "gps": [from_gps, to_gps],
    "gsm": [from_gsm, to_gsm],
    "hfsbe": [from_hfsbe, to_hfsbe],
    "hfsle": [from_hfsle, to_hfsle],
    "hfsdec": [from_hfsdec, to_hfsdec],
    "juliandec": [from_juliandec, to_juliandec],
    "julianhex": [from_julianhex, to_julianhex],
    "ksalnum": [from_ksalnum, to_ksalnum],
    "ksdec": [from_ksdec, to_ksdec],
    "leb128hex": [from_leb128hex, to_leb128hex],
    "linkedin": [from_linkedin, to_linkedin],
    "mastodon": [from_mastodon, to_mastodon],
    "metasploit": [from_metasploit, None],
    "dotnet": [from_dotnet, to_dotnet],
    "systemtime": [from_systemtime, to_systemtime],
    "dttm": [from_dttm, to_dttm],
    "ms1904": [from_ms1904, to_ms1904],
    "hotmail": [from_hotmail, to_hotmail],
    "msdos": [from_msdos, to_msdos],
    "moto": [from_moto, to_moto],
    "prtime": [from_prtime, to_prtime],
    "nokia": [from_nokia, to_nokia],
    "nokiale": [from_nokiale, to_nokiale],
    "ns40": [from_ns40, to_ns40],
    "ns40le": [from_ns40le, to_ns40le],
    "s32": [from_s32, to_s32],
    "semioctet": [from_semioctet, to_semioctet],
    "sony": [from_sony, to_sony],
    "symantec": [from_symantec, to_symantec],
    "tiktok": [from_tiktok, to_tiktok],
    "twitter": [from_twitter, to_twitter],
    "ulid": [from_ulid, to_ulid],
    "unixhex32be": [from_unixhex32be, to_unixhex32be],
    "unixhex32le": [from_unixhex32le, to_unixhex32le],
    "unixmilli": [from_unixmilli, to_unixmilli],
    "unixmillihex": [from_unixmillihex, to_unixmillihex],
    "unixsec": [from_unixsec, to_unixsec],
    "uuid": [from_uuid, to_uuid],
    "vm": [from_vm, to_vm],
    "cookie": [from_cookie, to_cookie],
    "filetimebe": [from_filetimebe, to_filetimebe],
    "filetimetle": [from_filetimele, to_filetimele],
    "filetimelohi": [from_filetimelohi, to_filetimelohi],
    "olebe": [from_olebe, to_olebe],
    "olele": [from_olele, to_olele],
    "oleauto": [from_oleauto, to_oleauto],
}


def main():
    """Parse all passed arguments"""
    now = dt.now(timezone.utc).strftime(__fmt__)
    arg_parse = argparse.ArgumentParser(
        description=f"Time Decoder and Converter v"
        f"{str(__version__)} - supporting "
        f"{str(__types__)} timestamps!\n\n"
        f"Some timestamps are only part of the entire value, and as such, full\n"
        f"timestamps may not be generated based on only the date/time portion.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    arg_parse.add_argument(
        "-g",
        "--gui",
        action="store_true",
        help="launch the gui",
    )
    arg_parse.add_argument(
        "--guess",
        metavar="TIMESTAMP",
        help="guess the timestamp format and output possibilities",
    )
    arg_parse.add_argument(
        "--timestamp",
        metavar="DATE",
        help="convert date to every timestamp\n"
        'enter date as "YYYY-MM-DD HH:MM:SS.f" in 24h fmt\n'
        "Without DATE argument, will convert current date/time\n",
        nargs="?",
        const=now,
    )
    arg_parse.add_argument(
        "--format",
        metavar="ARGUMENT",
        help=(
            "Display timestamp format and example by providing an available argument (without --)."
            "\nIf no argument is selected, all will be displayed."
        ),
        nargs="?",
        const="ALL",
    )
    for argument, data in ts_types.items():
        arg_parse.add_argument(f"--{argument}", metavar="", help=f"{data.ts_type}")
    arg_parse.add_argument(
        "--version", "-v", action="version", version=arg_parse.description
    )

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()

    args = arg_parse.parse_args()
    all_args = vars(args)
    try:
        if args.format:
            formats(args.format)
            sys.exit(0)
        if args.guess:
            full_list = from_all(args.guess)
            if len(full_list) == 0:
                print("[!] No valid dates found. Check your input and try again")
            else:
                print(
                    f"[+] Guessing timestamp format for {args.guess}\n"
                    f"[+] Outputs which do NOT result in a date/time value are NOT displayed\r"
                )
                if len(full_list) == 1:
                    dt_text = "date"
                else:
                    dt_text = "dates"
                print(
                    f"[+] Displaying {len(full_list)} potential {dt_text}\n"
                    f"{__red__}[+] Most likely results (+/- 5 years) are highlighted\n{__clr__}"
                )
                for _, output in enumerate(full_list):
                    print(f"{full_list[output][1]}")
            print("\r")
            return
        if args.timestamp:
            _, ts_outputs = to_timestamps(args.timestamp)
            print(
                f"\n[+] Converting {args.timestamp} to {len(ts_outputs)} timestamps:\n"
            )
            for ts_val in ts_outputs:
                print(ts_val)
            print("\r")
            return
        if args.gui:
            launch_gui()
        else:
            for arg_passed, _ in single_funcs.items():
                requested = all_args[arg_passed]
                if requested:
                    _, indiv_output, _, reason, _ = single_funcs[arg_passed][0](
                        requested
                    )
                    if indiv_output is False:
                        print(f"[!] {reason}")
                    else:
                        print(indiv_output)
                    return
    except Exception:
        handle(sys.exc_info())


if __name__ == "__main__":
    main()
