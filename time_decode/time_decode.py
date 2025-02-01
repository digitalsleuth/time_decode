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
import base64
import uuid
import traceback
from calendar import monthrange
from typing import NamedTuple
from zoneinfo import ZoneInfo as tzone, available_timezones as common_timezones
import juliandate as jd
from dateutil import parser as duparser
from colorama import init

# Included for GUI
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
    QGuiApplication,
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

common_timezones = common_timezones()
init(autoreset=True)

__author__ = "Corey Forman (digitalsleuth)"
__date__ = "30 Jan 2025"
__version__ = "9.0.0"
__description__ = "Python 3 CLI Date Time Conversion Tool"
__fmt__ = "%Y-%m-%d %H:%M:%S.%f"
__red__ = "\033[1;31m"
__clr__ = "\033[1;m"
__source__ = "https://github.com/digitalsleuth/time_decode"
__appname__ = f"Time Decode v{__version__}"

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
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMOGajm7g2n3sIFt4KmB
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
"""

try:
    from ctypes import windll

    AppId = f"digitalsleuth.time-decode.gui.v{__version__.replace('.','-')}"
    windll.shell32.SetCurrentProcessExplicitAppUserModelID(AppId)
except ImportError:
    pass


class NewWindow(QWidget):
    """This class sets the structure for a new window"""

    def __init__(self):
        """Sets up the new window table and context menu"""
        super().__init__()
        layout = QVBoxLayout()
        self.examplesLabel = QLabel()
        self.timestampTable = QTableWidget()
        self.timestampTable.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.timestampTable.setStyleSheet(
            "border: none; selection-background-color: #1644b9;"
        )
        self.timestampTable.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.context_menu = ContextMenu(self.timestampTable)
        self.timestampTable.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.timestampTable.customContextMenuRequested.connect(
            self.context_menu.show_context_menu
        )
        layout.addWidget(self.timestampTable)
        layout.addWidget(self.examplesLabel)
        self.setLayout(layout)

    def keyPressEvent(self, event):
        """Sets the Ctrl+C KeyPress for the window"""
        if event.matches(QKeySequence.StandardKey.Copy):
            self.context_menu.copy()
        else:
            super().keyPressEvent(event)


class AboutWindow(QWidget):
    """Sets the structure for the About window"""

    def __init__(self):
        super().__init__()
        layout = QGridLayout()
        self.aboutLabel = QLabel()
        self.urlLabel = QLabel()
        self.logoLabel = QLabel()
        spacer = QLabel()
        layout.addWidget(self.aboutLabel, 0, 0)
        layout.addWidget(spacer, 0, 1)
        layout.addWidget(self.urlLabel, 1, 0)
        layout.addWidget(self.logoLabel, 0, 2)
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


class UiDialog:
    """Sets the structure for the main user interface"""

    def __init__(self):
        self.d_width = 490
        self.d_height = 130
        self.text_font = QFont()
        self.text_font.setPointSize(9)
        self.results = {}
        self.examplesWindow = None
        self.newWindow = None

    def setupUi(self, Dialog):
        """Sets up the core UI"""
        if not Dialog.objectName():
            Dialog.setObjectName(__appname__)
        Dialog.setFixedWidth(self.d_width)
        Dialog.setMinimumHeight(self.d_height)
        Dialog.setStyleSheet(self.stylesheet)
        Dialog.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        Dialog.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowMaximizeButtonHint
        )
        self.screen_layout = QGuiApplication.primaryScreen().availableGeometry()
        self.scr_width, self.scr_height = (
            self.screen_layout.width(),
            self.screen_layout.height(),
        )
        self.center_x = (self.scr_width // 2) - (self.d_width // 2)
        self.center_y = (self.scr_height // 2) - (self.d_height // 2)
        Dialog.move(self.center_x, self.center_y)
        self.timestampText = QLineEdit(Dialog)
        self.timestampText.setObjectName("timestampText")
        self.timestampText.setGeometry(QRect(10, 30, 225, 22))
        self.timestampText.setHidden(False)
        self.timestampText.setEnabled(True)
        self.timestampText.setStyleSheet(self.stylesheet)
        self.timestampText.setFont(self.text_font)
        utc_time = dt.now(tzone("UTC"))
        self.dateTime = QDateTimeEdit(Dialog)
        self.dateTime.setObjectName("dateTime")
        self.dateTime.setDisplayFormat("yyyy-MM-dd HH:MM:ss")
        self.dateTime.setGeometry(QRect(10, 30, 225, 22))
        self.dateTime.setDateTime(utc_time)
        self.dateTime.setCalendarPopup(True)
        self.dateTime.calendarWidget().setFixedHeight(220)
        self.dateTime.calendarWidget().setGridVisible(True)
        self.dateTime.setHidden(True)
        self.dateTime.setEnabled(False)
        self.dateTime.setStyleSheet(self.stylesheet)
        self.dateTime.calendarWidget().setStyleSheet(
            "alternate-background-color: #EAF6FF; background-color: white; color: black;"
        )
        self.dateTime.setFont(self.text_font)
        self.dateTime.calendarWidget().setFont(self.text_font)
        self.nowButton = QPushButton("&Now", clicked=self.setNow)
        self.nowButton.setFont(self.text_font)
        self.updateButton = QPushButton(
            "&Update Time Zones", clicked=self.update_timezones
        )
        self.updateButton.setFont(self.text_font)
        self.buttonLayout = QHBoxLayout()
        self.buttonLayout.addWidget(self.nowButton)
        self.buttonLayout.addWidget(self.updateButton)
        self.calendarButtons = self.dateTime.calendarWidget().layout()
        self.calendarButtons.addLayout(self.buttonLayout)
        self.timestampFormats = QComboBox(Dialog)
        self.timestampFormats.setObjectName("timestampFormats")
        self.timestampFormats.setGeometry(QRect(10, 60, 225, 22))
        self.timestampFormats.setStyleSheet(
            "combobox-popup: 0; background-color: white; color: black;"
        )
        self.timestampFormats.view().setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.timestampFormats.setFont(self.text_font)
        types = {}
        for _, this_type in ts_types.items():
            types[this_type[0]] = this_type[1]
        types = dict(sorted(types.items(), key=lambda item: item[0].casefold()))
        for k, v in enumerate(types.items()):
            self.timestampFormats.addItem(v[0])
            self.timestampFormats.setItemData(k, v[1], Qt.ItemDataRole.ToolTipRole)
        self.timeZoneOffsets = QComboBox(Dialog)
        self.timeZoneOffsets.setObjectName("timeZoneOffsets")
        self.timeZoneOffsets.setGeometry(QRect(10, 90, 305, 22))
        self.timeZoneOffsets.setStyleSheet(
            "combobox-popup: 0; background-color: white; color: black;"
        )
        self.timeZoneOffsets.view().setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.timeZoneOffsets.setFont(self.text_font)
        ts_offsets = self.common_timezone_offsets()
        for k, v in enumerate(ts_offsets):
            self.timeZoneOffsets.addItem(f"{v[0]} {v[1]}")
            self.timeZoneOffsets.setItemData(k, v[1], Qt.ItemDataRole.ToolTipRole)
        self.timeZoneOffsets.setEnabled(True)
        self.timeZoneOffsets.setHidden(False)
        self.outputTable = QTableWidget(Dialog)
        self.outputTable.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.outputTable.setGeometry(QRect(10, 120, 440, 22))
        self.outputTable.setStyleSheet(
            "border: none; background-color: white; color: black; font-size: 10;"
        )
        self.outputTable.setVisible(False)
        self.outputTable.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOn
        )
        self.outputTable.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.context_menu = ContextMenu(self.outputTable)
        self.outputTable.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.outputTable.customContextMenuRequested.connect(
            self.context_menu.show_context_menu
        )
        self.outputTable.setFont(self.text_font)
        self.guessButton = QPushButton(Dialog)
        self.guessButton.setObjectName("guessButton")
        self.guessButton.setEnabled(True)
        self.guessButton.setHidden(False)
        self.guessButton.setGeometry(QRect(245, 30, 70, 22))
        self.guessButton.setStyleSheet("background-color: white; color: black;")
        self.guessButton.setFont(self.text_font)
        self.guessButton.clicked.connect(self.guess_decode)
        self.toallButton = QPushButton(Dialog)
        self.toallButton.setObjectName("toallButton")
        self.toallButton.setEnabled(False)
        self.toallButton.setHidden(True)
        self.toallButton.setGeometry(QRect(245, 30, 70, 22))
        self.toallButton.setStyleSheet("background-color: white; color: black;")
        self.toallButton.setFont(self.text_font)
        self.toallButton.clicked.connect(self.encode_toall)
        self.encodeRadio = QRadioButton(Dialog)
        self.encodeRadio.setObjectName("encodeRadio")
        self.encodeRadio.setGeometry(QRect(400, 30, 72, 20))
        self.encodeRadio.setStyleSheet("background-color: white; color: black;")
        self.encodeRadio.setFont(self.text_font)
        self.encodeRadio.toggled.connect(self._encode_select)
        self.decodeRadio = QRadioButton(Dialog)
        self.decodeRadio.setObjectName("decodeRadio")
        self.decodeRadio.setGeometry(QRect(325, 30, 72, 20))
        self.decodeRadio.setChecked(True)
        self.decodeRadio.setStyleSheet("background-color: white; color: black;")
        self.decodeRadio.setFont(self.text_font)
        self.decodeRadio.toggled.connect(self._decode_select)
        self.goButton = QPushButton(Dialog)
        self.goButton.setObjectName("goButton")
        self.goButton.setGeometry(QRect(245, 60, 70, 22))
        self.goButton.setStyleSheet("background-color: white; color: black;")
        self.goButton.setFont(self.text_font)
        self.goButton.clicked.connect(self.go_function)
        new_window_pixmap = QStyle.StandardPixmap.SP_ArrowRight
        icon = self.style().standardIcon(new_window_pixmap)
        self.newWindowButton = QPushButton(Dialog)
        self.newWindowButton.setObjectName("newWindowButton")
        self.newWindowButton.setGeometry(QRect(325, 90, 22, 22))
        self.newWindowButton.setStyleSheet(
            "background-color: white; color: black; border: 0;"
        )
        self.newWindowButton.setFont(self.text_font)
        self.newWindowButton.setIcon(icon)
        self.newWindowButton.setIconSize(QSize(22, 22))
        self.newWindowButton.setToolTip("Open results in a new window")
        self.newWindowButton.clicked.connect(self._new_window)
        self.retranslateUi(Dialog)
        QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        """Retranslate the Ui"""
        _translate = QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", __appname__))
        self.dateTime.setDisplayFormat(
            _translate("Dialog", "yyyy-MM-dd HH:mm:ss", None)
        )
        self.timestampText.setPlaceholderText(_translate("Dialog", "Timestamp", None))
        self.guessButton.setText(_translate("Dialog", "Guess", None))
        self.toallButton.setText(_translate("Dialog", "To All", None))
        self.encodeRadio.setText(_translate("Dialog", "Encode", None))
        self.decodeRadio.setText(_translate("Dialog", "Decode", None))
        self.goButton.setText(_translate("Dialog", "\u2190 From", None))
        self.newWindowButton.setHidden(True)
        self.newWindowButton.setEnabled(False)
        self._menu_bar()

    def setNow(self):
        """Sets the current date / time on the Calendar Widget"""
        today = QDate().currentDate()
        now = dt.now(tzone("UTC"))
        self.dateTime.calendarWidget().setSelectedDate(today)
        self.dateTime.setDateTime(now)

    def update_timezones(self):
        """Updates the timeZoneOffsets combo box to reflect the selected Calendar date/time"""
        ts_offsets = self.common_timezone_offsets()
        self.timeZoneOffsets.clear()
        for k, v in enumerate(ts_offsets):
            self.timeZoneOffsets.addItem(f"{v[0]} {v[1]}")
            self.timeZoneOffsets.setItemData(k, v[1], Qt.ItemDataRole.ToolTipRole)

    def _decode_select(self):
        """Sets the structure for the decode radio button"""
        self.dateTime.setHidden(True)
        self.dateTime.setEnabled(False)
        self.timestampText.setHidden(False)
        self.timestampText.setEnabled(True)
        self.guessButton.setEnabled(True)
        self.guessButton.setHidden(False)
        self.toallButton.setEnabled(False)
        self.toallButton.setHidden(True)
        self.goButton.setText("\u2190 From")
        self.newWindowButton.setHidden(True)
        self.newWindowButton.setEnabled(False)
        self._reset_table()

    def _encode_select(self):
        """Sets the structure for the encode radio button"""
        self.timestampText.setHidden(True)
        self.timestampText.setEnabled(False)
        self.dateTime.setHidden(False)
        self.dateTime.setEnabled(True)
        self.guessButton.setEnabled(False)
        self.guessButton.setHidden(True)
        self.toallButton.setEnabled(True)
        self.toallButton.setHidden(False)
        self.goButton.setText("\u2190 To")
        self.newWindowButton.setHidden(True)
        self.newWindowButton.setEnabled(False)
        self._reset_table()

    def _reset_table(self):
        """Resets the GUI structure"""
        self.adjustSize()
        self.setFixedWidth(490)
        self.setFixedHeight(130)
        self.outputTable.setVisible(False)
        self.outputTable.clearContents()
        self.outputTable.setColumnCount(0)
        self.outputTable.setRowCount(0)
        self.outputTable.reset()
        self.outputTable.setStyleSheet("border: none")

    def guess_decode(self):
        """Will take the provided timestamp and run it through the 'from_all' function"""
        timestamp = self.timestampText.text()
        selected_tz = self.timeZoneOffsets.currentText()
        if timestamp == "":
            self._msg_box("You must enter a timestamp!", "Info")
            return
        all_ts = from_all(timestamp)
        results = {}
        for k, _ in all_ts.items():
            if "No Time Zone Change" in selected_tz:
                results[k] = f"{all_ts[k][0]} {all_ts[k][2]}"
            else:
                tz_offset = selected_tz.split(" ")[0]
                tz_name = " ".join(selected_tz.split(" ")[1:])
                tz = tzone(tz_name)
                tz_original = all_ts[k][0]
                dt_parse = duparser.parse(tz_original)
                dt_obj = dt_parse.replace(tzinfo=timezone.utc)
                tz_selected = dt_obj.astimezone(tz).strftime(__fmt__)
                if self.check_daylight(dt_parse, tz):
                    tz_out = f"{tz_offset} DST"
                else:
                    tz_out = tz_offset
                results[k] = f"{tz_selected} {tz_out}"
        self.results = results
        self.display_output(results)

    def encode_toall(self):
        """Takes the dateTime object, passes it to the to_timestamps function which encodes it"""
        dt_obj = self.dateTime.text()
        selected_tz = self.timeZoneOffsets.currentText()
        if "No Time Zone Change" not in selected_tz:
            tz_name = " ".join(selected_tz.split(" ")[1:])
            tz = tzone(tz_name)
            dt_parse = duparser.parse(dt_obj)
            dt_parse = dt_parse.replace(tzinfo=timezone.utc)
            dt_obj = dt_parse.astimezone(tz).strftime(__fmt__)
        results, _ = to_timestamps(dt_obj)
        self.results = results
        self.display_output(results)

    def common_timezone_offsets(self):
        """Generates a list of common timezones for conversion"""
        timezone_offsets = [("No Time Zone Change", "")]
        dt_obj = duparser.parse(self.dateTime.text())
        dt_obj_naive = dt_obj.replace(tzinfo=timezone.utc)
        for tz_name in common_timezones:
            set_timezone = tzone(tz_name)
            dt_val = dt_obj_naive.astimezone(set_timezone)
            offset_seconds = dt_val.utcoffset().total_seconds()
            hours, remainder = divmod(abs(offset_seconds), 3600)
            minutes = remainder // 60
            sign = "+" if offset_seconds >= 0 else "-"
            int_offset = f"{sign}{int(hours):02}:{int(minutes):02}"
            formatted_offset = f"UTC{int_offset}"
            timezone_offsets.append((formatted_offset, tz_name))
        timezone_offsets.sort(key=lambda x: x[0])
        return timezone_offsets

    def display_output(self, ts_list):
        """Configures the output format for the provided values"""
        self._reset_table()
        self.outputTable.setVisible(True)
        self.outputTable.setColumnCount(2)
        self.outputTable.setAlternatingRowColors(True)
        self.outputTable.setStyleSheet(
            """
            border: none;
            alternate-background-color: #EAF6FF;
            background-color: white;
            color: black;
            selection-background-color: #1644b9;
            """
        )
        for ts_type, result in ts_list.items():
            row = self.outputTable.rowCount()
            self.outputTable.insertRow(row)
            widget0 = QTableWidgetItem(ts_types[ts_type][0])
            widget0.setFlags(widget0.flags() & ~Qt.ItemFlag.ItemIsEditable)
            widget0.setToolTip(ts_types[ts_type][1])
            widget1 = QTableWidgetItem(result)
            widget1.setFlags(widget1.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.outputTable.setItem(row, 0, widget0)
            self.outputTable.item(row, 0).setTextAlignment(
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            )
            self.outputTable.setItem(row, 1, widget1)
            self.outputTable.item(row, 1).setTextAlignment(
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            )
            if self.decodeRadio.isChecked():
                if "DST" in result:
                    ts = result.split(" DST")[0]
                else:
                    ts = result
                this_yr = int(dt.now().strftime("%Y"))
                if int(duparser.parse(ts).strftime("%Y")) in range(
                    this_yr - 5, this_yr + 5
                ):
                    for each_col in range(0, self.outputTable.columnCount()):
                        this_col = self.outputTable.item(row, each_col)
                        this_col.setBackground(QColor("lightgreen"))
                        this_col.setForeground(QColor("black"))
        self.outputTable.horizontalHeader().setFixedHeight(1)
        self.outputTable.verticalHeader().setFixedWidth(1)
        self.outputTable.setFixedWidth(540)
        self.outputTable.setColumnWidth(0, 220)
        self.outputTable.setColumnWidth(1, 300)
        self.outputTable.resizeRowsToContents()
        self.outputTable.setShowGrid(True)
        total_row_height = sum(
            self.outputTable.rowHeight(row)
            for row in range(self.outputTable.rowCount())
        )
        self.outputTable.setFixedHeight(400)
        if total_row_height > 500:
            self.setFixedHeight(540)
            self.outputTable.verticalScrollBar().show()
        else:
            self.setFixedHeight(self.height() + int(total_row_height + 1))
            self.outputTable.verticalScrollBar().hide()
        self.setFixedWidth(555)
        self.newWindowButton.setEnabled(True)
        self.newWindowButton.setHidden(False)

    def go_function(self):
        """The To/From button: converts a date/timestamp, depending on the selected radio button"""
        results = {}
        ts_format = self.timestampFormats.currentText()
        ts_text = self.timestampText.text()
        ts_date = self.dateTime.text()
        selected_tz = self.timeZoneOffsets.currentText()
        if "No Time Zone Change" not in selected_tz:
            tz_name = " ".join(selected_tz.split(" ")[1:])
            tz_offset = selected_tz.split(" ")[0]
            tz = tzone(tz_name)
            dt_parse = duparser.parse(ts_date)
            dt_parse = dt_parse.replace(tzinfo=timezone.utc)
            ts_date = dt_parse.astimezone(tz).strftime(__fmt__)
        in_ts_types = [k for k, v in ts_types.items() if ts_format in v]
        if not in_ts_types:
            self._msg_box(
                f"For some reason {ts_format} is not in the list of available conversions!",
                "Error",
            )
            return
        ts_type = in_ts_types[0]
        if self.encodeRadio.isChecked():
            is_func = False
            ts_selection = f"to_{ts_type}"
            for this_func in to_funcs:
                if inspect.isfunction(this_func):
                    func_name = this_func.__name__
                    if func_name == ts_selection:
                        is_func = True
            if not is_func:
                self._msg_box(
                    f"Cannot convert to {ts_format},\nrequired information is unavailable.",
                    "Warning",
                )
                return
            ts_func = globals()[ts_selection]
            result, _ = ts_func(ts_date)
            results[ts_type] = result
            self.results = results
            self.display_output(results)
        elif self.decodeRadio.isChecked():
            is_func = False
            if ts_text == "":
                self._msg_box("You must enter a timestamp!", "Info")
                return
            ts_selection = f"from_{ts_type}"
            for this_func in from_funcs:
                if inspect.isfunction(this_func):
                    func_name = this_func.__name__
                    if func_name == ts_selection:
                        is_func = True
            if not is_func:
                self._msg_box(
                    f"Cannot convert from {ts_format},\nrequired information is unavailable.",
                    "Warning",
                )
                return
            ts_func = globals()[ts_selection]
            result, _, _, reason, tz_out = ts_func(ts_text)
            if not result:
                self._msg_box(reason, "Error")
                return
            if "No Time Zone Change" not in selected_tz:
                dt_parse = duparser.parse(result)
                dt_obj = dt_parse.replace(tzinfo=timezone.utc)
                result = dt_obj.astimezone(tz).strftime(__fmt__)
                if self.check_daylight(dt_parse, tz):
                    tz_out = f"{tz_offset} DST"
                else:
                    tz_out = tz_offset
            results[ts_type] = f"{result} {tz_out}"
            self.results = results
            self.display_output(results)

    @staticmethod
    def check_daylight(dtval, tz):
        """Checks to see if the provided timestamp, in the provided timezone, is observing DST"""
        dst_check = tz.localize(dtval)
        return dst_check.dst() != timedelta(0, 0)

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
        self.msg_box.setText(f"{message}\t    ")
        self.msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        self.msg_box.exec()

    def _about(self):
        self.about_window = AboutWindow()
        self.about_window.setWindowFlags(
            self.about_window.windowFlags() & ~Qt.WindowType.WindowMinMaxButtonsHint
        )
        githubLink = f'<a href="{__source__}">View the source on GitHub</a>'
        self.about_window.setWindowTitle("About")
        self.about_window.aboutLabel.setText(
            f"Version: {__appname__}\nLast Updated: {__date__}\nAuthor: {__author__}"
        )
        self.about_window.aboutLabel.setFont(self.text_font)
        self.about_window.urlLabel.setOpenExternalLinks(True)
        self.about_window.urlLabel.setText(githubLink)
        self.about_window.urlLabel.setFont(self.text_font)
        self.logo = QPixmap()
        self.logo.loadFromData(base64.b64decode(__fingerprint__))
        self.about_window.logoLabel.setPixmap(self.logo)
        self.about_window.logoLabel.resize(20, 20)
        about_width = self.about_window.width()
        about_height = self.about_window.height()
        self.about_window.move(
            self.center_x + (about_width // 4), self.center_y + (about_height // 4)
        )
        self.about_window.show()

    def _examples(self):
        if self.examplesWindow is None:
            structures = {}
            for _, data_list in ts_types.items():
                structures[data_list[0]] = (
                    data_list[1],
                    data_list[2],
                )
            structures = sorted(
                structures.items(), key=lambda item: item[1][0].casefold()
            )
            self.examplesWindow = NewWindow()
            self.examplesWindow.examplesLabel.setGeometry(QRect(0, 0, 200, 24))
            self.examplesWindow.examplesLabel.setText(
                "Timestamps displayed here are based on the date 2023-05-01 between 09:00 & 18:00"
            )
            self.examplesWindow.examplesLabel.setFont(self.text_font)
            self.examplesWindow.setWindowTitle("Timestamp Examples")
            self.examplesWindow.setStyleSheet(
                """
                border: none; alternate-background-color: #EAF6FF;
                background-color: white; color: black;
                """
            )
            self.examplesWindow.timestampTable.setColumnCount(2)
            for example in structures:
                row = self.examplesWindow.timestampTable.rowCount()
                self.examplesWindow.timestampTable.insertRow(row)
                widget0 = QTableWidgetItem(example[1][0])
                widget0.setFlags(widget0.flags() & ~Qt.ItemFlag.ItemIsEditable)
                widget0.setToolTip(example[0])
                widget1 = QTableWidgetItem(example[1][1])
                widget1.setFlags(widget1.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.examplesWindow.timestampTable.setItem(row, 0, widget0)
                self.examplesWindow.timestampTable.item(row, 0).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
                self.examplesWindow.timestampTable.item(row, 0)
                self.examplesWindow.timestampTable.setItem(row, 1, widget1)
                self.examplesWindow.timestampTable.item(row, 1).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
            self.examplesWindow.timestampTable.horizontalHeader().setFixedHeight(1)
            self.examplesWindow.timestampTable.verticalHeader().setFixedWidth(1)
            self.examplesWindow.timestampTable.setGeometry(
                QRect(
                    0,
                    0,
                    self.examplesWindow.timestampTable.horizontalHeader().length(),
                    self.examplesWindow.timestampTable.verticalHeader().length(),
                )
            )
            self.examplesWindow.timestampTable.resizeColumnsToContents()
            self.examplesWindow.timestampTable.resizeRowsToContents()
            self.examplesWindow.timestampTable.setShowGrid(True)
            self.examplesWindow.timestampTable.setAlternatingRowColors(True)
            self.examplesWindow.setFixedSize(
                self.examplesWindow.timestampTable.horizontalHeader().length() + 48,
                400,
            )
            self.examplesWindow.timestampTable.setFont(self.text_font)
            self.examplesWindow.show()
        else:
            self.examplesWindow.close()
            self.examplesWindow = None
            self._examples()

    def _new_window(self):
        table_data = self.results
        selected_tz = self.timeZoneOffsets.currentText()
        msg = title = ""
        if self.encodeRadio.isChecked():
            entered_value = self.dateTime.text()
            title = f"Encoded: {entered_value}"
            if "No Time Zone Change" not in selected_tz:
                entered_value = f"{entered_value} {selected_tz}"
            msg = f"Encoded: {entered_value}"
        elif self.decodeRadio.isChecked():
            entered_value = self.timestampText.text()
            title = f"Decoded: {entered_value}"
            if "No Time Zone Change" not in selected_tz:
                entered_value = f"{entered_value} {selected_tz}"
            msg = f"Decoded: {entered_value}"
        if self.newWindow is None:
            self.newWindow = NewWindow()
            self.newWindow.windowLabel = self.newWindow.examplesLabel
            self.newWindow.windowLabel.setGeometry(QRect(0, 0, 200, 24))
            self.newWindow.windowLabel.setText(msg)
            self.newWindow.examplesLabel.setFont(self.text_font)
            self.newWindow.setWindowTitle(title)
            self.newWindow.setStyleSheet(
                """
                border: none; alternate-background-color: #EAF6FF;
                background-color: white; color: black;
                """
            )
            self.newWindow.timestampTable.setColumnCount(2)
            for ts_type, result in table_data.items():
                row = self.newWindow.timestampTable.rowCount()
                self.newWindow.timestampTable.insertRow(row)
                widget0 = QTableWidgetItem(ts_types[ts_type][0])
                widget0.setFlags(widget0.flags() & ~Qt.ItemFlag.ItemIsEditable)
                widget0.setToolTip(ts_types[ts_type][1])
                widget1 = QTableWidgetItem(result)
                widget1.setFlags(widget1.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.newWindow.timestampTable.setItem(row, 0, widget0)
                self.newWindow.timestampTable.item(row, 0).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
                self.newWindow.timestampTable.item(row, 0)
                self.newWindow.timestampTable.setItem(row, 1, widget1)
                self.newWindow.timestampTable.item(row, 1).setTextAlignment(
                    int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                )
                if self.decodeRadio.isChecked():
                    this_yr = int(dt.now().strftime("%Y"))
                    if int(duparser.parse(result).strftime("%Y")) in range(
                        this_yr - 5, this_yr + 5
                    ):
                        for each_col in range(
                            0, self.newWindow.timestampTable.columnCount()
                        ):
                            this_col = self.newWindow.timestampTable.item(row, each_col)
                            this_col.setBackground(QColor("lightgreen"))
                            this_col.setForeground(QColor("black"))
            self.newWindow.timestampTable.horizontalHeader().setFixedHeight(1)
            self.newWindow.timestampTable.verticalHeader().setFixedWidth(1)
            self.newWindow.timestampTable.setGeometry(
                QRect(
                    0,
                    0,
                    self.newWindow.timestampTable.horizontalHeader().length(),
                    self.newWindow.timestampTable.verticalHeader().length(),
                )
            )
            self.newWindow.timestampTable.resizeColumnsToContents()
            for col in range(0, self.newWindow.timestampTable.columnCount()):
                col_width = self.newWindow.timestampTable.columnWidth(col)
                self.newWindow.timestampTable.setColumnWidth(col, col_width + 10)
            self.newWindow.timestampTable.resizeRowsToContents()
            row_height = self.newWindow.timestampTable.rowHeight(row)
            total_row_height = sum(
                row_height for row in range(self.newWindow.timestampTable.rowCount())
            )
            if total_row_height < 400:
                window_height = total_row_height + (row_height * 2) + 8
            else:
                window_height = 400
            self.newWindow.timestampTable.setShowGrid(True)
            self.newWindow.timestampTable.setAlternatingRowColors(True)
            self.newWindow.setFixedSize(
                self.newWindow.timestampTable.horizontalHeader().length() + 38,
                window_height,
            )
            self.newWindow.timestampTable.setFont(self.text_font)
            self.newWindow.show()
        else:
            self.newWindow.close()
            self.newWindow = None
            self._new_window()


class TimeDecodeGui(QMainWindow, UiDialog):
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

    def __init__(self):
        """Call and setup the UI"""
        super().__init__()
        self.setupUi(self)

    def keyPressEvent(self, event):
        """Create a KeyPress event for a Ctrl+C (Copy) event for selected text"""
        if event.matches(QKeySequence.StandardKey.Copy):
            self.context_menu.copy()
        else:
            super().keyPressEvent(event)


# End PyQt6 GUI

# 2023-05-01 17:59:38.285777
# Examples based around 2023-05-01 09:xx:xx to 17:xx:xx


class TsTypes(NamedTuple):
    ts_type: str
    reason: str
    example: str
    time_zone: str


ts_types = {
    "unix_sec": TsTypes(
        "Unix Seconds",
        "Unix seconds timestamp is 10 digits in length",
        "1682963978",
        "UTC",
    ),
    "unix_milli": TsTypes(
        "Unix Milliseconds",
        "Unix milliseconds timestamp is 13 digits in length",
        "1682963978285",
        "UTC",
    ),
    "unix_milli_hex": TsTypes(
        "Unix Milliseconds hex",
        "Unix Milliseconds hex timestamp is 12 hex characters (6 bytes)",
        "0187d878582d",
        "UTC",
    ),
    "windows_hex_64": TsTypes(
        "Windows 64-bit Hex BE",
        "Windows 64-bit Hex Big-Endian timestamp is 16 hex characters (8 bytes)",
        "01d97c56b232fc2a",
        "UTC",
    ),
    "windows_hex_64le": TsTypes(
        "Windows 64-bit Hex LE",
        "Windows 64-bit Hex Little-Endian timestamp is 16 hex characters (8 bytes)",
        "2afc32b2567cd901",
        "UTC",
    ),
    "chrome": TsTypes(
        "Google Chrome",
        "Chrome/Webkit timestamp is 17 digits",
        "13327437578285777",
        "UTC",
    ),
    "ad": TsTypes(
        "Active Directory/LDAP",
        "Active Directory/LDAP timestamps are 18 digits",
        "133274375782857770",
        "UTC",
    ),
    "unix_hex_32be": TsTypes(
        "Unix Hex 32-bit BE",
        "Unix Hex 32-bit Big-Endian timestamps are 8 hex characters (4 bytes)",
        "644ffe0a",
        "UTC",
    ),
    "unix_hex_32le": TsTypes(
        "Unix Hex 32-bit LE",
        "Unix Hex 32-bit Little-Endian timestamps are 8 hex characters (4 bytes)",
        "0afe4f64",
        "UTC",
    ),
    "cookie": TsTypes(
        "Windows Cookie Date",
        "IE text cookie times consist of 2 ints, enter with a comma between them",
        "2986828032,31030358",
        "UTC",
    ),
    "ole_be": TsTypes(
        "Windows OLE 64-bit double BE",
        "OLE Big-Endian timestamps are 16 hex characters (8 bytes)",
        "40e5fef7fdf0f084",
        "UTC",
    ),
    "ole_le": TsTypes(
        "Windows OLE 64-bit double LE",
        "OLE Little-Endian timestamps are 16 hex characters (8 bytes)",
        "84f0f0fdf7fee540",
        "UTC",
    ),
    "mac": TsTypes(
        "NSDate - Mac Absolute time",
        "NSDates (Mac) are 9 digits '.' 6 digits",
        "704656778.285777",
        "UTC",
    ),
    "hfs_dec": TsTypes(
        "Mac OS/HFS+ Decimal Time",
        "Mac OS/HFS+ Decimal timestamps are 10 digits",
        "3765808778",
        "UTC",
    ),
    "hfs_be": TsTypes(
        "HFS/HFS+ 32-bit Hex BE",
        "HFS/HFS+ Big-Endian timestamps are 8 hex characters (4 bytes)",
        "e075ae8a",
        "HFS Local / HFS+ UTC",
    ),
    "hfs_le": TsTypes(
        "HFS/HFS+ 32-bit Hex LE",
        "HFS/HFS+ Little-Endian timestamps are 8 hex characters (4 bytes)",
        "8aae75e0",
        "HFS Local / HFS+ UTC",
    ),
    "msdos": TsTypes(
        "MS-DOS 32-bit Hex Value",
        "MS-DOS 32-bit timestamps are 8 hex characters (4 bytes)",
        "738fa156",
        "Local",
    ),
    "fat": TsTypes(
        "FAT Date + Time",
        "MS-DOS wFatDate wFatTime timestamps are 8 hex characters (4 bytes)",
        "a156738f",
        "Local",
    ),
    "systemtime": TsTypes(
        "Microsoft 128-bit SYSTEMTIME",
        "Microsoft 128-bit SYSTEMTIME timestamps are 32 hex characters (16 bytes)",
        "e70705000100010011003b0026001d01",
        "UTC",
    ),
    "filetime": TsTypes(
        "Microsoft FILETIME time",
        "FILETIME timestamps are 2 sets of 8 hex chars (4 bytes) separated by a colon",
        "b232fc2a:01d97c56",
        "UTC",
    ),
    "hotmail": TsTypes(
        "Microsoft Hotmail time",
        "Hotmail timestamps are 2 sets of 8 hex chars (4 bytes), separated by a colon",
        "567cd901:2afc32b2",
        "UTC",
    ),
    "prtime": TsTypes(
        "Mozilla PRTime",
        "Mozilla PRTime timestamps are 16 digits",
        "1682963978285777",
        "UTC",
    ),
    "ole_auto": TsTypes(
        "OLE Automation Date",
        "OLE Automation timestamps are 2 ints, separated by a dot",
        "45047.749748677976",
        "UTC",
    ),
    "ms1904": TsTypes(
        "MS Excel 1904 Date",
        "Excel 1904 timestamps are 2 ints, separated by a dot",
        "43585.749748677976",
        "UTC",
    ),
    "iostime": TsTypes(
        "NSDate - iOS 11+",
        "NSDates (iOS) are 15-19 digits in length",
        "704656778285777024",
        "UTC",
    ),
    "symtime": TsTypes(
        "Symantec AV time",
        "Symantec 6-byte hex timestamps are 12 hex characters",
        "350401113b26",
        "UTC",
    ),
    "gpstime": TsTypes("GPS time", "GPS timestamps are 10 digits", "1366999159", "UTC"),
    "eitime": TsTypes(
        "Google EI time",
        "Google ei timestamps contain only URLsafe base64 characters: A-Za-z0-9=-_",
        "Cv5PZA",
        "UTC",
    ),
    "bplist": TsTypes(
        "NSDate - Binary Plist / Cocoa",
        "NSDates (bplist) are 9 digits in length",
        "704656778",
        "UTC",
    ),
    "nsdate": TsTypes(
        "NSDate - bplist / Cocoa / Mac / iOS",
        "NSDates are 9, 9.6, or 15-19 digits in length",
        "704656778.285777",
        "UTC",
    ),
    "gsm": TsTypes(
        "GSM time",
        "GSM timestamps are 14 hex characters (7 bytes)",
        "32501071958300",
        "UTC",
    ),
    "vm": TsTypes(
        "VMSD time",
        "VMSD values are a 6-digit value and a signed/unsigned int at least 9 digits",
        "391845,-1777068416",
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
        "1653078434443132928",
        "UTC",
    ),
    "discord": TsTypes(
        "Discord time",
        "Discord timestamps are 18 digits or longer",
        "1102608904745127937",
        "UTC",
    ),
    "ksalnum": TsTypes(
        "KSUID Alpha-numeric",
        "KSUID values are 27 alpha-numeric characters",
        "2PChRqPZDwT9m2gBDLd5uy7XNTr",
        "UTC",
    ),
    "mastodon": TsTypes(
        "Mastodon time",
        "Mastodon timestamps are 18 digits or longer",
        "110294727262208000",
        "UTC",
    ),
    "metasploit": TsTypes(
        "Metasploit Payload UUID",
        "Metasploit Payload UUID's are at least 22 chars and base64 urlsafe encoded",
        "4PGoVGYmx8l6F3sVI4Rc8g",
        "UTC",
    ),
    "sony": TsTypes(
        "Sonyflake time",
        "Sonyflake values are 15 hex characters",
        "65dd4bb89000001",
        "UTC",
    ),
    "uuid": TsTypes(
        "UUID time",
        "UUIDs are in the format 00000000-0000-0000-0000-000000000000",
        "d93026f0-e857-11ed-a05b-0242ac120003",
        "UTC",
    ),
    "dhcp6": TsTypes(
        "DHCP6 DUID time",
        "DHCPv6 DUID values are at least 14 bytes long",
        "000100012be2ba8a000000000000",
        "UTC",
    ),
    "dotnet": TsTypes(
        "Microsoft .NET DateTime",
        ".NET DateTime values are 18 digits",
        "638185607782857728",
        "UTC",
    ),
    "gbound": TsTypes(
        "GMail Boundary time",
        "GMail Boundary values are 28 hex chars",
        "0000000000001872d105faa59600",
        "UTC",
    ),
    "gmsgid": TsTypes(
        "GMail Message ID time",
        "GMail Message ID values are 16 hex chars or 19 digits (IMAP)",
        "187d878582d00000",
        "UTC",
    ),
    "moto": TsTypes(
        "Motorola time",
        "Motorola 6-byte hex timestamps are 12 hex characters",
        "350501113b26",
        "UTC",
    ),
    "nokia": TsTypes(
        "Nokia time",
        "Nokia 4-byte hex timestamps are 8 hex characters",
        "cdd5880a",
        "UTC",
    ),
    "nokiale": TsTypes(
        "Nokia time LE",
        "Nokia 4-byte hex timestamps are 8 hex characters",
        "0a88d5cd",
        "UTC",
    ),
    "ns40": TsTypes(
        "Nokia S40 time",
        "Nokia 7-byte hex timestamps are 14 hex characters",
        "07e70501113b26",
        "UTC",
    ),
    "ns40le": TsTypes(
        "Nokia S40 time LE",
        "Nokia 7-byte hex timestamps are 14 hex characters",
        "e7070501113b26",
        "UTC",
    ),
    "bitdec": TsTypes(
        "Bitwise Decimal time",
        "Bitwise Decimal timestamps are 10 digits",
        "2121600123",
        "Local",
    ),
    "bitdate": TsTypes(
        "BitDate time",
        "Samsung/LG BitDate timestamps are 8 hex characters",
        "7b0c757e",
        "Local",
    ),
    "ksdec": TsTypes(
        "KSUID Decimal",
        "KSUID decimal timestamps are 9 digits in length",
        "282963978",
        "UTC",
    ),
    "exfat": TsTypes(
        "exFAT time",
        "exFAT 32-bit timestamps are 8 hex characters (4 bytes)",
        "56a18f73",
        "Local",
    ),
    "biomehex": TsTypes(
        "Apple Biome hex time",
        "Apple Biome Hex value is 8 bytes (16 chars) long",
        "41c5001ac5249457",
        "UTC",
    ),
    "biome64": TsTypes(
        "Apple Biome 64-bit decimal",
        "Apple Biome 64-bit decimal is 19 digits in length",
        "4739194297853973591",
        "UTC",
    ),
    "s32": TsTypes(
        "S32 Encoded (Bluesky) time",
        "S32 encoded (Bluesky) timestamps are 9 characters long",
        "3kzgbkpsk",
        "UTC",
    ),
    "apache": TsTypes(
        "Apache Cookie Hex time",
        "Apache Cookie hex timestamps are 13 hex characters long",
        "5faa420b70880",
        "UTC",
    ),
    "leb128_hex": TsTypes(
        "LEB128 Hex time",
        "LEB128 Hex timestamps are variable-length and even-length",
        "8ed1b7b8fd30",
        "UTC",
    ),
    "julian_dec": TsTypes(
        "Julian Date decimal value",
        "Julian Date decimal values are 7 digits, a decimal, and up to 10 digits",
        "2460066.249748678",
        "UTC",
    ),
    "julian_hex": TsTypes(
        "Julian Date hex value",
        "Julian Date hex values are 14 characters (7 bytes)",
        "2589a2ee2dcc6",
        "UTC",
    ),
    "semi_octet": TsTypes(
        "Semi-Octet decimal value",
        "Semi-Octet decimal values are 12 or 14 digits long",
        "325010901034",
        "Local",
    ),
}
__types__ = len(ts_types)

epochs = {
    1: dt(1, 1, 1),
    1601: dt(1601, 1, 1),
    1899: dt(1899, 12, 30),
    1904: dt(1904, 1, 1),
    1970: dt(1970, 1, 1),
    1980: dt(1980, 1, 6, tzinfo=timezone.utc),
    2000: dt(2000, 1, 1),
    2001: dt(2001, 1, 1),
    2050: dt(2050, 1, 1),
    "hundreds_nano": 10000000,
    "nano_2001": 1000000000,
    "active": 116444736000000000,
    "hfs_dec_sub": 2082844800,
    "kstime": 1400000000,
}

# There have been no further leapseconds since 2017,1,1 at the __date__ of this script
# which is why the leapseconds end with a dt.now object to valid/relevant timestamp output.
# See REFERENCES.md for source info.
leapseconds = {
    10: [dt(1972, 1, 1), dt(1972, 7, 1)],
    11: [dt(1972, 7, 1), dt(1973, 1, 1)],
    12: [dt(1973, 1, 1), dt(1974, 1, 1)],
    13: [dt(1974, 1, 1), dt(1975, 1, 1)],
    14: [dt(1975, 1, 1), dt(1976, 1, 1)],
    15: [dt(1976, 1, 1), dt(1977, 1, 1)],
    16: [dt(1977, 1, 1), dt(1978, 1, 1)],
    17: [dt(1978, 1, 1), dt(1979, 1, 1)],
    18: [dt(1979, 1, 1), dt(1980, 1, 1)],
    19: [dt(1980, 1, 1), dt(1981, 7, 1)],
    20: [dt(1981, 7, 1), dt(1982, 7, 1)],
    21: [dt(1982, 7, 1), dt(1983, 7, 1)],
    22: [dt(1983, 7, 1), dt(1985, 7, 1)],
    23: [dt(1985, 7, 1), dt(1988, 1, 1)],
    24: [dt(1988, 1, 1), dt(1990, 1, 1)],
    25: [dt(1990, 1, 1), dt(1991, 1, 1)],
    26: [dt(1991, 1, 1), dt(1992, 7, 1)],
    27: [dt(1992, 7, 1), dt(1993, 7, 1)],
    28: [dt(1993, 7, 1), dt(1994, 7, 1)],
    29: [dt(1994, 7, 1), dt(1996, 1, 1)],
    30: [dt(1996, 1, 1), dt(1997, 7, 1)],
    31: [dt(1997, 7, 1), dt(1999, 1, 1)],
    32: [dt(1999, 1, 1), dt(2006, 1, 1)],
    33: [dt(2006, 1, 1), dt(2009, 1, 1)],
    34: [dt(2009, 1, 1), dt(2012, 7, 1)],
    35: [dt(2012, 7, 1), dt(2015, 7, 1)],
    36: [dt(2015, 7, 1), dt(2017, 1, 1)],
    37: [dt(2017, 1, 1), dt.now() - timedelta(seconds=37)],
}

S32_CHARS = "234567abcdefghijklmnopqrstuvwxyz"


def launch_gui():
    """Execute the application"""
    td_app = QApplication([__appname__, "windows:darkmode=2"])
    icon = QPixmap()
    icon.loadFromData(base64.b64decode(__fingerprint__))
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


def analyze(args):
    """Process arguments and errors"""
    all_args = vars(args)
    try:
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
                print(f"[+] Displaying {len(full_list)} potential {dt_text}\r")
                print(
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
        for arg_passed, _ in single_funcs.items():
            if all_args[arg_passed]:
                _, indiv_output, _, reason, _ = single_funcs[arg_passed](
                    all_args[arg_passed]
                )
                if indiv_output is False:
                    print(f"[!] {reason}")
                else:
                    print(indiv_output)
                return
    except Exception:
        handle(sys.exc_info())


def from_unix_sec(timestamp):
    """Convert Unix Seconds value to a date"""
    ts_type, reason, _, tz_out = ts_types["unix_sec"]
    try:
        if len(str(timestamp)) != 10 or not timestamp.isdigit():
            in_unix_sec = indiv_output = combined_output = False
        else:
            in_unix_sec = dt.fromtimestamp(float(timestamp), timezone.utc).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_unix_sec} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_unix_sec} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_sec = indiv_output = combined_output = False
    return in_unix_sec, indiv_output, combined_output, reason, tz_out


def to_unix_sec(dt_val):
    """Convert date to a Unix Seconds value"""
    ts_type, _, _, _ = ts_types["unix_sec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_unix_sec = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        ts_output = str(f"{ts_type}:\t\t\t{out_unix_sec}")
    except Exception:
        handle(sys.exc_info())
        out_unix_sec = ts_output = False
    return out_unix_sec, ts_output


def from_unix_milli(timestamp):
    """Convert Unix Millisecond value to a date"""
    ts_type, reason, _, tz_out = ts_types["unix_milli"]
    try:
        if len(str(timestamp)) != 13 or not str(timestamp).isdigit():
            in_unix_milli = indiv_output = combined_output = False
        else:
            in_unix_milli = dt.fromtimestamp(
                float(timestamp) / 1000.0, timezone.utc
            ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_unix_milli} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_milli} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_milli = indiv_output = combined_output = False
    return in_unix_milli, indiv_output, combined_output, reason, tz_out


def to_unix_milli(dt_val):
    """Convert date to a Unix Millisecond value"""
    ts_type, _, _, _ = ts_types["unix_milli"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_unix_milli = str(
            int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000)
        )
        ts_output = str(f"{ts_type}:\t\t{out_unix_milli}")
    except Exception:
        handle(sys.exc_info())
        out_unix_milli = ts_output = False
    return out_unix_milli, ts_output


def from_unix_milli_hex(timestamp):
    """Convert a Unix Millisecond hex value to a date"""
    ts_type, reason, _, tz_out = ts_types["unix_milli_hex"]
    try:
        if len(str(timestamp)) != 12 or not all(
            char in hexdigits for char in timestamp
        ):
            in_unix_milli_hex = indiv_output = combined_output = False
        else:
            unix_mil = int(str(timestamp), 16)
            in_unix_milli_hex, _, _, _, _ = from_unix_milli(unix_mil)
            indiv_output = str(f"{ts_type}: {in_unix_milli_hex} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_milli_hex} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_milli_hex = indiv_output = combined_output = False
    return in_unix_milli_hex, indiv_output, combined_output, reason, tz_out


def to_unix_milli_hex(dt_val):
    """Convert a date to a Unix Millisecond hex value"""
    ts_type, _, _, _ = ts_types["unix_milli_hex"]
    try:
        unix_mil, _ = to_unix_milli(dt_val)
        out_unix_milli_hex = f"{int(unix_mil):012x}"
        ts_output = str(f"{ts_type}:\t\t{out_unix_milli_hex}")
    except Exception:
        handle(sys.exc_info())
        out_unix_milli_hex = ts_output = False
    return out_unix_milli_hex, ts_output


def from_windows_hex_64(timestamp):
    """Convert a Windows 64 Hex Big-Endian value to a date"""
    ts_type, reason, _, tz_out = ts_types["windows_hex_64"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_windows_hex_64 = indiv_output = combined_output = False
        else:
            base10_microseconds = int(timestamp, 16) / 10
            if base10_microseconds >= 1e17:
                in_windows_hex_64 = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1601] + timedelta(microseconds=base10_microseconds)
                in_windows_hex_64 = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_windows_hex_64} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_windows_hex_64} " f"UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_windows_hex_64 = indiv_output = combined_output = False
    return in_windows_hex_64, indiv_output, combined_output, reason, tz_out


def to_windows_hex_64(dt_val):
    """Convert a date to a Windows 64 Hex Big-Endian value"""
    ts_type, _, _, _ = ts_types["windows_hex_64"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        out_windows_hex_64 = str(hex(int(calc_time) * 10))[2:].zfill(16)
        ts_output = str(f"{ts_type}:\t\t{out_windows_hex_64}")
    except Exception:
        handle(sys.exc_info())
        out_windows_hex_64 = ts_output = False
    return out_windows_hex_64, ts_output


def from_windows_hex_64le(timestamp):
    """Convert a Windows 64 Hex Little-Endian value to a date"""
    ts_type, reason, _, tz_out = ts_types["windows_hex_64le"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_windows_hex_le = indiv_output = combined_output = False
        else:
            indiv_output = combined_output = False
            endianness_change = int.from_bytes(
                struct.pack("<Q", int(timestamp, 16)), "big"
            )
            converted_time = endianness_change / 10
            if converted_time >= 1e17:
                in_windows_hex_le = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1601] + timedelta(microseconds=converted_time)
                in_windows_hex_le = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_windows_hex_le} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_windows_hex_le} " f"UTC{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_windows_hex_le = indiv_output = combined_output = False
    return in_windows_hex_le, indiv_output, combined_output, reason, tz_out


def to_windows_hex_64le(dt_val):
    """Convert a date to a Windows 64 Hex Little-Endian value"""
    ts_type, _, _, _ = ts_types["windows_hex_64le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        out_windows_hex_le = str(struct.pack("<Q", int(calc_time * 10)).hex()).zfill(16)
        ts_output = str(f"{ts_type}:\t\t{out_windows_hex_le}")
    except Exception:
        handle(sys.exc_info())
        out_windows_hex_le = ts_output = False
    return out_windows_hex_le, ts_output


def from_chrome(timestamp):
    """Convert a Chrome Timestamp/Webkit Value to a date"""
    ts_type, reason, _, tz_out = ts_types["chrome"]
    try:
        if not len(timestamp) == 17 or not timestamp.isdigit():
            in_chrome = indiv_output = combined_output = False
        else:
            delta = timedelta(microseconds=int(timestamp))
            converted_time = epochs[1601] + delta
            in_chrome = converted_time.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_chrome} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_chrome} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_chrome = indiv_output = combined_output = False
    return in_chrome, indiv_output, combined_output, reason, tz_out


def to_chrome(dt_val):
    """Convert a date to a Chrome Timestamp/Webkit value"""
    ts_type, _, _, _ = ts_types["chrome"]
    try:
        dt_obj = duparser.parse(dt_val)
        nano_seconds = ""
        if "." in dt_val:
            nano_seconds = dt_val.split(".")[1].split(" ")[0]
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        micro_seconds = (dt_obj - epochs[1601]).microseconds
        chrome_time = (dt_obj - epochs[1601]).total_seconds() - int(dt_tz)
        chrome_micro = str(chrome_time).split(".")[1]
        if (
            (len(nano_seconds) == 6 and len(chrome_micro) < 6)
            or len(nano_seconds) > 6
            or len(nano_seconds) == 6
        ):
            chrome_time = str(chrome_time).replace(
                str(chrome_time).split(".")[1], str(micro_seconds).zfill(6)
            )
            out_chrome = str(chrome_time).replace(".", "")
        else:
            out_chrome = str(int(chrome_time * 1000000))
        ts_output = str(f"{ts_type}:\t\t\t{out_chrome}")
    except Exception:
        handle(sys.exc_info())
        out_chrome = ts_output = False
    return out_chrome, ts_output


def from_ad(timestamp):
    """Convert an Active Directory/LDAP timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["ad"]
    try:
        if not len(timestamp) == 18 or not timestamp.isdigit():
            in_ad = indiv_output = combined_output = False
        else:
            val_check = (
                float(int(timestamp) - epochs["active"]) / epochs["hundreds_nano"]
            )
            if val_check < 0 or val_check >= 32536799999:
                # This is the Windows maximum for parsing a unix TS
                # and is 3001-01-19 02:59:59 UTC                
                in_ad = indiv_output = combined_output = False
            else:
                dt_obj = dt.fromtimestamp(val_check, timezone.utc)
                in_ad = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_ad} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_ad} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_ad = indiv_output = combined_output = False
    return in_ad, indiv_output, combined_output, reason, tz_out


def to_ad(dt_val):
    """Convert a date to an Active Directory/LDAP timestamp"""
    ts_type, _, _, _ = ts_types["ad"]
    try:
        nano_seconds = ""
        if "." in dt_val:
            nano_seconds = dt_val.split(".")[1].split(" ")[0]
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
            dt_obj = duparser.parse(dt_val, ignoretz=True)
        else:
            dt_tz = 0
            dt_obj = duparser.parse(dt_val, ignoretz=True)
        if len(nano_seconds) == 7:
            dt_obj = dt_obj.replace(microsecond=0)
            nano_seconds = int(nano_seconds)
        elif len(nano_seconds) > 7:
            dt_obj = dt_obj.replace(microsecond=0)
            nano_seconds = int(nano_seconds[: -(len(nano_seconds) - 7)])
        elif len(nano_seconds) == 6 or (
            len(nano_seconds) == 5 and len(str(dt_obj.microsecond)) == 6
        ):
            nano_seconds = dt_obj.microsecond * 10
            dt_obj = dt_obj.replace(microsecond=0)
        else:
            nano_seconds = 0
        tz_shift = (
            int(
                ((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
                * epochs["hundreds_nano"]
            )
            + nano_seconds
        )
        out_adtime = str(int(tz_shift) + int(epochs["active"]))
        ts_output = str(f"{ts_type}:\t\t{out_adtime}")
    except Exception:
        handle(sys.exc_info())
        out_adtime = ts_output = False
    return out_adtime, ts_output


def from_unix_hex_32be(timestamp):
    """Convert a Unix Hex 32-bit Big-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["unix_hex_32be"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_unix_hex_32 = indiv_output = combined_output = False
        else:
            to_dec = int(timestamp, 16)
            in_unix_hex_32 = dt.fromtimestamp(float(to_dec), timezone.utc).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_unix_hex_32} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_hex_32} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_hex_32 = indiv_output = combined_output = False
    return in_unix_hex_32, indiv_output, combined_output, reason, tz_out


def to_unix_hex_32be(dt_val):
    """Convert a date to a Unix Hex 32-bit Big-Endian timestamp"""
    ts_type, _, _, _ = ts_types["unix_hex_32be"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
        out_unix_hex_32 = str(struct.pack(">L", unix_time).hex())
        ts_output = str(f"{ts_type}:\t\t{out_unix_hex_32}")
    except Exception:
        handle(sys.exc_info())
        out_unix_hex_32 = ts_output = False
    return out_unix_hex_32, ts_output


def from_unix_hex_32le(timestamp):
    """Convert a Unix Hex 32-bit Little-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["unix_hex_32le"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_unix_hex_32le = indiv_output = combined_output = False
        else:
            to_dec = int.from_bytes(struct.pack("<L", int(timestamp, 16)), "big")
            in_unix_hex_32le = dt.fromtimestamp(float(to_dec), timezone.utc).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_unix_hex_32le} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_unix_hex_32le} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_unix_hex_32le = indiv_output = combined_output = False
    return in_unix_hex_32le, indiv_output, combined_output, reason, tz_out


def to_unix_hex_32le(dt_val):
    """Convert a date to a Unix Hex 32-bit Little-Endian timestamp"""
    ts_type, _, _, _ = ts_types["unix_hex_32le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
        out_unix_hex_32le = str(struct.pack("<L", unix_time).hex())
        ts_output = str(f"{ts_type}:\t\t{out_unix_hex_32le}")
    except Exception:
        handle(sys.exc_info())
        out_unix_hex_32le = ts_output = False
    return out_unix_hex_32le, ts_output


def from_cookie(timestamp):
    """Convert an Internet Explorer timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["cookie"]
    try:
        if not ("," in timestamp) or not (
            timestamp.split(",")[0].isdigit() and timestamp.split(",")[1].isdigit()
        ):
            in_cookie = indiv_output = combined_output = False
        else:
            low, high = [int(h, base=10) for h in timestamp.split(",")]
            calc = 10**-7 * (high * 2**32 + low) - 11644473600
            if calc >= 32536799999 or calc < 0:
                in_cookie = indiv_output = combined_output = False
            else:
                dt_obj = dt.fromtimestamp(calc, timezone.utc)
                in_cookie = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_cookie} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_cookie} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_cookie = indiv_output = combined_output = False
    return in_cookie, indiv_output, combined_output, reason, tz_out


def to_cookie(dt_val):
    """Convert a date to Internet Explorer timestamp values"""
    ts_type, _, _, _ = ts_types["cookie"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz))
        high = int(((unix_time + 11644473600) * 10**7) / 2**32)
        low = int((unix_time + 11644473600) * 10**7) - (high * 2**32)
        out_cookie = f"{str(low)},{str(high)}"
        ts_output = str(f"{ts_type}:\t\t{out_cookie}")
    except Exception:
        handle(sys.exc_info())
        out_cookie = ts_output = False
    return out_cookie, ts_output


def from_ole_be(timestamp):
    """Convert an OLE Big-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["ole_be"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_ole_be = indiv_output = combined_output = False
        else:
            delta = struct.unpack(">d", struct.pack(">Q", int(timestamp, 16)))[0]
            if int(delta) < 0 or int(delta) > 2e6:
                in_ole_be = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1899] + timedelta(days=delta)
                in_ole_be = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_ole_be} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_ole_be} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_ole_be = indiv_output = combined_output = False
    return in_ole_be, indiv_output, combined_output, reason, tz_out


def to_ole_be(dt_val):
    """Convert a date to an OLE Big-Endian timestamp"""
    ts_type, _, _, _ = ts_types["ole_be"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        delta = ((dt_obj - epochs[1899]).total_seconds() - int(dt_tz)) / 86400
        conv = struct.unpack("<Q", struct.pack("<d", delta))[0]
        out_ole_be = str(struct.pack(">Q", conv).hex())
        ts_output = str(f"{ts_type}:\t{out_ole_be}")
    except Exception:
        handle(sys.exc_info())
        out_ole_be = ts_output = False
    return out_ole_be, ts_output


def from_ole_le(timestamp):
    """Convert an OLE Little-Endian timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["ole_le"]
    try:
        if not len(timestamp) == 16 or not all(char in hexdigits for char in timestamp):
            in_ole_le = indiv_output = combined_output = False
        else:
            to_le = hex(int.from_bytes(struct.pack("<Q", int(timestamp, 16)), "big"))
            delta = struct.unpack(">d", struct.pack(">Q", int(to_le[2:], 16)))[0]
            if int(delta) < 0 or int(delta) > 99999:
                in_ole_le = indiv_output = combined_output = False
            else:
                dt_obj = epochs[1899] + timedelta(days=delta)
                in_ole_le = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_ole_le} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_ole_le} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_ole_le = indiv_output = combined_output = False
    return in_ole_le, indiv_output, combined_output, reason, tz_out


def to_ole_le(dt_val):
    """Convert a date to an OLE Little-Endian timestamp"""
    ts_type, _, _, _ = ts_types["ole_le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        delta = ((dt_obj - epochs[1899]).total_seconds() - int(dt_tz)) / 86400
        conv = struct.unpack("<Q", struct.pack("<d", delta))[0]
        out_ole_le = str(struct.pack("<Q", conv).hex())
        ts_output = str(f"{ts_type}:\t{out_ole_le}")
    except Exception:
        handle(sys.exc_info())
        out_ole_le = ts_output = False
    return out_ole_le, ts_output


def from_bplist(timestamp):
    """Convert a bplist NSDate timestamp to a date value"""
    in_nsdate, indiv_output, combined_output, _, _ = from_nsdate(timestamp)
    _, reason, _, tz_out = ts_types["bplist"]
    if not "(bplist)" in indiv_output:
        in_nsdate = indiv_output = combined_output = False
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def from_iostime(timestamp):
    """Convert an iOS NSDate timestamp to a date value"""
    in_nsdate, indiv_output, combined_output, _, _ = from_nsdate(timestamp)
    _, reason, _, tz_out = ts_types["iostime"]
    if not "(iOS)" in indiv_output:
        in_nsdate = indiv_output = combined_output = False
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def from_mac(timestamp):
    """Convert a mac NSDate timestamp to a date value"""
    in_nsdate, indiv_output, combined_output, _, _ = from_nsdate(timestamp)
    _, reason, _, tz_out = ts_types["mac"]
    if not "(Mac)" in indiv_output:
        in_nsdate = indiv_output = combined_output = False
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def from_nsdate(timestamp):
    """Convert an Apple NSDate timestamp (Mac Absolute, BPlist, Cocoa, iOS) to a date"""
    val_type = ""
    ts_type, reason, _, tz_out = None, None, None, None
    try:
        in_nsdate = indiv_output = combined_output = None
        if (
            "." in timestamp
            and (
                (len(timestamp.split(".")[0]) == 9)
                and (len(timestamp.split(".")[1]) in range(0, 7))
            )
            and "".join(timestamp.split(".")).isdigit()
        ):
            ts_type, reason, _, tz_out = ts_types["mac"]
            val_type = "mac"
        elif len(timestamp) == 9 and timestamp.isdigit():
            ts_type, reason, _, tz_out = ts_types["bplist"]
            val_type = "bplist"
        elif len(timestamp) in range(15, 19) and timestamp.isdigit():
            ts_type, reason, _, tz_out = ts_types["iostime"]
            val_type = "iostime"
        else:
            in_nsdate = indiv_output = combined_output = False
        if val_type in {"mac", "bplist"}:
            dt_obj = epochs[2001] + timedelta(seconds=float(timestamp))
            in_nsdate = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_nsdate}")
            combined_output = str(f"{__red__}{ts_type}:\t{in_nsdate} {tz_out}{__clr__}")
        elif val_type == "iostime":
            dt_obj = (int(timestamp) / int(epochs["nano_2001"])) + 978307200
            in_nsdate = dt.fromtimestamp(dt_obj, timezone.utc).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_nsdate} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_nsdate} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_nsdate = indiv_output = combined_output = False
    return in_nsdate, indiv_output, combined_output, reason, tz_out


def to_mac(dt_val):
    """Convert a date to a Mac Absolute timestamp"""
    ts_type, _, _, _ = ts_types["mac"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        mac_ts = (
            int(
                ((dt_obj - epochs[2001]).total_seconds() - int(dt_tz))
                * epochs["nano_2001"]
            )
            / 1000000000
        )
        if mac_ts < 0:
            out_mac = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_mac = str(f"{mac_ts:.6f}")
        ts_output = str(f"{ts_type}:\t{out_mac}")
    except Exception:
        handle(sys.exc_info())
        out_mac = ts_output = False
    return out_mac, ts_output


def from_hfs_dec(timestamp):
    """Convert a Mac OS/HFS+ Decimal Timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["hfs_dec"]
    try:
        if len(str(timestamp)) != 10 or not (timestamp).isdigit():
            in_hfs_dec = indiv_output = combined_output = False
        else:
            minus_epoch = float(int(timestamp) - epochs["hfs_dec_sub"])
            if minus_epoch < 0:
                in_hfs_dec = indiv_output = combined_output = False
            else:
                in_hfs_dec = dt.fromtimestamp(minus_epoch, timezone.utc).strftime(
                    __fmt__
                )
                indiv_output = str(f"{ts_type}: {in_hfs_dec} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_hfs_dec} {tz_out}{__clr__}"
                )
    except Exception:
        in_hfs_dec = indiv_output = combined_output = False
        handle(sys.exc_info())
    return in_hfs_dec, indiv_output, combined_output, reason, tz_out


def to_hfs_dec(dt_val):
    """Convert a date to a Mac OS/HFS+ Decimal Timestamp"""
    ts_type, _, _, _ = ts_types["hfs_dec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_hfs_dec = str(int((dt_obj - epochs[1904]).total_seconds() - int(dt_tz)))
        ts_output = str(f"{ts_type}:\t{out_hfs_dec}")
    except Exception:
        handle(sys.exc_info())
        out_hfs_dec = ts_output = False
    return out_hfs_dec, ts_output


def from_hfs_be(timestamp):
    """Convert an HFS/HFS+ Big-Endian timestamp to a date (HFS+ is in UTC)"""
    ts_type, reason, _, tz_out = ts_types["hfs_be"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_hfs_be = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1904] + timedelta(seconds=int(timestamp, 16))
            in_hfs_be = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_hfs_be} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_hfs_be} " f"{tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_hfs_be = indiv_output = combined_output = False
    return in_hfs_be, indiv_output, combined_output, reason, tz_out


def to_hfs_be(dt_val):
    """Convert a date to an HFS/HFS+ Big-Endian timestamp"""
    ts_type, _, _, _ = ts_types["hfs_be"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        conv = int((dt_obj - epochs[1904]).total_seconds() - int(dt_tz))
        if conv > 4294967295:
            out_hfs_be = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_hfs_be = f"{conv:08x}"
        ts_output = str(f"{ts_type}:\t\t{out_hfs_be}")
    except Exception:
        handle(sys.exc_info())
        out_hfs_be = ts_output = False
    return out_hfs_be, ts_output


def from_hfs_le(timestamp):
    """Convert an HFS/HFS+ Little-Endian timestamp to a date (HFS+ is in UTC)"""
    ts_type, reason, _, tz_out = ts_types["hfs_le"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_hfs_le = indiv_output = combined_output = False
        else:
            to_le = struct.unpack(">I", struct.pack("<I", int(timestamp, 16)))[0]
            dt_obj = epochs[1904] + timedelta(seconds=to_le)
            in_hfs_le = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_hfs_le} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_hfs_le} " f"{tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_hfs_le = indiv_output = combined_output = False
    return in_hfs_le, indiv_output, combined_output, reason, tz_out


def to_hfs_le(dt_val):
    """Convert a date to an HFS/HFS+ Little-Endian timestamp"""
    ts_type, _, _, _ = ts_types["hfs_le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        conv = int((dt_obj - epochs[1904]).total_seconds() - int(dt_tz))
        if conv > 4294967295:
            out_hfs_le = "[!] Timestamp Boundary Exceeded [!]"
        else:
            out_hfs_le = str(struct.pack("<I", conv).hex())
        ts_output = str(f"{ts_type}:\t\t{out_hfs_le}")
    except Exception:
        handle(sys.exc_info())
        out_hfs_le = ts_output = False
    return out_hfs_le, ts_output


def from_fat(timestamp):
    """Convert an MS-DOS wFatDate wFatTime timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["fat"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_fat = indiv_output = combined_output = False
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
            if any(
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
            ):
                in_fat = indiv_output = combined_output = False
            else:
                dt_obj = dt(fat_year, fat_month, fat_day, fat_hour, fat_min, fat_sec)
                in_fat = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_fat} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_fat} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_fat = indiv_output = combined_output = False
    return in_fat, indiv_output, combined_output, reason, tz_out


def to_fat(dt_val):
    """Convert a date to an MS-DOS wFatDate wFatTime timestamp"""
    ts_type, _, _, _ = ts_types["fat"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = str(f"{ts_type}:\t\t{out_fat}")
    except Exception:
        handle(sys.exc_info())
        out_fat = ts_output = False
    return out_fat, ts_output


def from_msdos(timestamp):
    """Convert an MS-DOS timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["msdos"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_msdos = indiv_output = combined_output = False
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
            if any(
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
            ):
                in_msdos = indiv_output = combined_output = False
            else:
                dt_obj = dt(dos_year, dos_month, dos_day, dos_hour, dos_min, dos_sec)
                in_msdos = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_msdos} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_msdos} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_msdos = indiv_output = combined_output = False
    return in_msdos, indiv_output, combined_output, reason, tz_out


def to_msdos(dt_val):
    """Convert a date to an MS-DOS timestamp"""
    ts_type, _, _, _ = ts_types["msdos"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = str(f"{ts_type}:\t{out_msdos}")
    except Exception:
        handle(sys.exc_info())
        out_msdos = ts_output = False
    return out_msdos, ts_output


def from_exfat(timestamp):
    """Convert an exFAT timestamp (LE) to a date"""
    ts_type, reason, _, tz_out = ts_types["exfat"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_exfat = indiv_output = combined_output = False
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
            if any(
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
            ):
                in_exfat = indiv_output = combined_output = False
            else:
                dt_obj = dt(
                    exfat_year, exfat_month, exfat_day, exfat_hour, exfat_min, exfat_sec
                )
                in_exfat = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_exfat} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_exfat} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_exfat = indiv_output = combined_output = False
    return in_exfat, indiv_output, combined_output, reason, tz_out


def to_exfat(dt_val):
    """Convert a date to an exFAT timestamp (LE)"""
    ts_type, _, _, _ = ts_types["exfat"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = str(f"{ts_type}:\t\t\t{out_exfat}")
    except Exception:
        handle(sys.exc_info())
        out_exfat = ts_output = False
    return out_exfat, ts_output


def from_systemtime(timestamp):
    """Convert a Microsoft 128-bit SYSTEMTIME timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["systemtime"]
    try:
        if not len(timestamp) == 32 or not all(char in hexdigits for char in timestamp):
            in_systemtime = indiv_output = combined_output = False
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
                in_systemtime = indiv_output = combined_output = False
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
            indiv_output = str(f"{ts_type}: {in_systemtime} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t{in_systemtime} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_systemtime = indiv_output = combined_output = False
    return in_systemtime, indiv_output, combined_output, reason, tz_out


def to_systemtime(dt_val):
    """Convert a date to a Microsoft 128-bit SYSTEMTIME timestamp"""
    ts_type, _, _, _ = ts_types["systemtime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        micro = int(dt_obj.microsecond / 1000)
        tz_shift = dt_obj.timestamp() - int(dt_tz)
        add_micro = (tz_shift * 1000) + micro
        convert_to_seconds = add_micro / 1000
        new_dt_obj = dt.fromtimestamp(convert_to_seconds)
        full_date = new_dt_obj.strftime("%Y, %m, %w, %d, %H, %M, %S, " + str(micro))
        stamp = []
        for val in full_date.split(","):
            to_hex = int(
                hex(int.from_bytes(struct.pack("<H", int(val)), "big"))[2:], 16
            )
            stamp.append(f"{to_hex:04x}")
        out_systemtime = "".join(stamp)
        ts_output = str(f"{ts_type}:\t{out_systemtime}")
    except Exception:
        handle(sys.exc_info())
        out_systemtime = ts_output = False
    return out_systemtime, ts_output


def from_filetime(timestamp):
    """Convert a Microsoft FILETIME timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["filetime"]
    try:
        if not (":" in timestamp) or not (
            all(char in hexdigits for char in timestamp[0:8])
            and all(char in hexdigits for char in timestamp[9:])
        ):
            in_filetime = indiv_output = combined_output = False
        else:
            part2, part1 = [int(h, base=16) for h in timestamp.split(":")]
            converted_time = struct.unpack(">Q", struct.pack(">LL", part1, part2))[0]
            if converted_time >= 1e18:
                in_filetime = indiv_output = combined_output = False
            else:
                dt_obj = dt.fromtimestamp(
                    float(converted_time - epochs["active"]) / epochs["hundreds_nano"],
                    timezone.utc,
                )
                in_filetime = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_filetime} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_filetime} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_filetime = indiv_output = combined_output = False
    return in_filetime, indiv_output, combined_output, reason, tz_out


def to_filetime(dt_val):
    """Convert a date to a Microsoft FILETIME timestamp"""
    ts_type, _, _, _ = ts_types["filetime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        indiv_output = str(struct.pack(">Q", int(calc_time * 10)).hex())
        out_filetime = f"{str(indiv_output[8:])}:{str(indiv_output[:8])}"
        ts_output = str(f"{ts_type}:\t{out_filetime}")
    except Exception:
        handle(sys.exc_info())
        out_filetime = ts_output = False
    return out_filetime, ts_output


def from_hotmail(timestamp):
    """Convert a Microsoft Hotmail timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["hotmail"]
    try:
        if ":" not in timestamp or not (
            all(char in hexdigits for char in timestamp[0:8])
            and all(char in hexdigits for char in timestamp[9:])
        ):
            in_hotmail = indiv_output = combined_output = False
        else:
            hm_repl = timestamp.replace(":", "")
            byte_swap = "".join(
                [hm_repl[i : i + 2] for i in range(0, len(hm_repl), 2)][::-1]
            )
            part2 = int(byte_swap[:8], base=16)
            part1 = int(byte_swap[8:], base=16)
            converted_time = struct.unpack(">Q", struct.pack(">LL", part1, part2))[0]
            if converted_time >= 1e18:
                in_hotmail = indiv_output = combined_output = False
            else:
                dt_obj = dt.fromtimestamp(
                    float(converted_time - epochs["active"]) / epochs["hundreds_nano"],
                    timezone.utc,
                )
                in_hotmail = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_hotmail} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_hotmail} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_hotmail = indiv_output = combined_output = False
    return in_hotmail, indiv_output, combined_output, reason, tz_out


def to_hotmail(dt_val):
    """Convert a date to a Microsoft Hotmail timestamp"""
    ts_type, _, _, _ = ts_types["hotmail"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        minus_epoch = dt_obj - epochs[1601]
        calc_time = (
            minus_epoch.microseconds
            + ((minus_epoch.seconds - int(dt_tz)) * 1000000)
            + (minus_epoch.days * 86400000000)
        )
        indiv_output = str(struct.pack(">Q", int(calc_time * 10)).hex())
        byte_swap = "".join(
            [indiv_output[i : i + 2] for i in range(0, len(indiv_output), 2)][::-1]
        )
        out_hotmail = f"{str(byte_swap[8:])}:{str(byte_swap[:8])}"
        ts_output = str(f"{ts_type}:\t\t{out_hotmail}")
    except Exception:
        handle(sys.exc_info())
        out_hotmail = ts_output = False
    return out_hotmail, ts_output


def from_prtime(timestamp):
    """Convert a Mozilla PRTime timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["prtime"]
    try:
        if not len(timestamp) == 16 or not timestamp.isdigit():
            in_prtime = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1970] + timedelta(microseconds=int(timestamp))
            in_prtime = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_prtime} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_prtime} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_prtime = indiv_output = combined_output = False
    return in_prtime, indiv_output, combined_output, reason, tz_out


def to_prtime(dt_val):
    """Convert a date to Mozilla's PRTime timestamp"""
    ts_type, _, _, _ = ts_types["prtime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_prtime = str(
            int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000)
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_prtime}")
    except Exception:
        handle(sys.exc_info())
        out_prtime = ts_output = False
    return out_prtime, ts_output


def from_ole_auto(timestamp):
    """Convert an OLE Automation timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["ole_auto"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 5)
                and (len(timestamp.split(".")[1]) in range(9, 13))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_ole_auto = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1899] + timedelta(days=float(timestamp))
            in_ole_auto = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ole_auto} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_ole_auto} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_ole_auto = indiv_output = combined_output = False
    return in_ole_auto, indiv_output, combined_output, reason, tz_out


def to_ole_auto(dt_val):
    """Convert a date to an OLE Automation timestamp"""
    ts_type, _, _, _ = ts_types["ole_auto"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        ole_ts = ((dt_obj - epochs[1899]).total_seconds() - int(dt_tz)) / 86400
        out_ole_auto = f"{ole_ts:.12f}"
        ts_output = str(f"{ts_type}:\t\t{out_ole_auto}")
    except Exception:
        handle(sys.exc_info())
        out_ole_auto = ts_output = False
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
            in_ms1904 = indiv_output = combined_output = False
        else:
            dt_obj = epochs[1904] + timedelta(days=float(timestamp))
            in_ms1904 = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ms1904} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_ms1904} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_ms1904 = indiv_output = combined_output = False
    return in_ms1904, indiv_output, combined_output, reason, tz_out


def to_ms1904(dt_val):
    """Convert a date to a Microsoft Excel 1904 timestamp"""
    ts_type, _, _, _ = ts_types["ms1904"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        ms1904_ts = ((dt_obj - epochs[1904]).total_seconds() - int(dt_tz)) / 86400
        out_ms1904 = f"{ms1904_ts:.12f}"
        ts_output = str(f"{ts_type}:\t\t{out_ms1904}")
    except Exception:
        handle(sys.exc_info())
        out_ms1904 = ts_output = False
    return out_ms1904, ts_output


def to_iostime(dt_val):
    """Convert a date to an iOS 11 timestamp"""
    ts_type, _, _, _ = ts_types["iostime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_iostime = str(
            int(
                ((dt_obj - epochs[2001]).total_seconds() - int(dt_tz))
                * epochs["nano_2001"]
            )
        )
        if int(out_iostime) < 0:
            out_iostime = "[!] Timestamp Boundary Exceeded [!]"
        ts_output = str(f"{ts_type}:\t\t{out_iostime}")
    except Exception:
        handle(sys.exc_info())
        out_iostime = ts_output = False
    return out_iostime, ts_output


def from_symtime(timestamp):
    """Convert a Symantec 6-byte hex timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["symtime"]
    try:
        if not len(timestamp) == 12 or not all(char in hexdigits for char in timestamp):
            in_symtime = indiv_output = combined_output = False
        else:
            hex_to_dec = [
                int(timestamp[i : i + 2], 16) for i in range(0, len(timestamp), 2)
            ]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            hex_to_dec[1] = hex_to_dec[1] + 1
            if hex_to_dec[1] not in range(1, 13):
                in_symtime = indiv_output = combined_output = False
            else:
                dt_obj = dt(
                    hex_to_dec[0],
                    hex_to_dec[1],
                    hex_to_dec[2],
                    hex_to_dec[3],
                    hex_to_dec[4],
                    hex_to_dec[5],
                )
                in_symtime = dt_obj.strftime(__fmt__)
        indiv_output = str(f"{ts_type}: {in_symtime}")
        combined_output = str(f"{__red__}{ts_type}:\t\t{in_symtime} {tz_out}{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_symtime = indiv_output = combined_output = False
    return in_symtime, indiv_output, combined_output, reason, tz_out


def to_symtime(dt_val):
    """Convert a date to Symantec's 6-byte hex timestamp"""
    ts_type, _, _, _ = ts_types["symtime"]
    try:
        dt_obj = duparser.parse(dt_val)
        sym_year = f"{(dt_obj.year - 1970):02x}"
        sym_month = f"{(dt_obj.month - 1):02x}"
        sym_day = f"{(dt_obj.day):02x}"
        sym_hour = f"{(dt_obj.hour):02x}"
        sym_minute = f"{(dt_obj.minute):02x}"
        sym_second = f"{(dt_obj.second):02x}"
        out_symtime = (
            f"{sym_year}{sym_month}{sym_day}{sym_hour}{sym_minute}{sym_second}"
        )
        ts_output = str(f"{ts_type}:\t\t{out_symtime}")
    except Exception:
        handle(sys.exc_info())
        out_symtime = ts_output = False
    return out_symtime, ts_output


def from_gpstime(timestamp):
    """Convert a GPS timestamp to a date (involves leap seconds)"""
    ts_type, reason, _, tz_out = ts_types["gpstime"]
    try:
        if not len(timestamp) == 10 or not timestamp.isdigit():
            in_gpstime = indiv_output = combined_output = False
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
            indiv_output = str(f"{ts_type}: {in_gpstime}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_gpstime} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_gpstime = indiv_output = combined_output = False
    return in_gpstime, indiv_output, combined_output, reason, tz_out


def to_gpstime(dt_val):
    """Convert a date to a GPS timestamp (involves leap seconds)"""
    ts_type, _, _, _ = ts_types["gpstime"]
    try:
        check_date = duparser.parse(dt_val)
        if hasattr(check_date.tzinfo, "_offset"):
            dt_tz = check_date.tzinfo._offset.total_seconds()
            check_date = duparser.parse(dt_val, ignoretz=True)
        else:
            dt_tz = 0
            check_date = duparser.parse(dt_val, ignoretz=True)
        for entry in leapseconds:
            check = date_range(
                leapseconds.get(entry)[0], leapseconds.get(entry)[1], check_date
            )
            if check is True:
                variance = entry
            else:
                variance = 0
        leap_correction = check_date + timedelta(seconds=variance)
        epoch_shift = leap_correction - epochs[1970]
        gps_stamp = (
            dt.fromtimestamp(epoch_shift.total_seconds(), timezone.utc) - epochs[1980]
        ).total_seconds() - 19
        gps_stamp = int(gps_stamp) - int(dt_tz)
        out_gpstime = str(gps_stamp)
        ts_output = str(f"{ts_type}:\t\t\t{out_gpstime}")
    except Exception:
        handle(sys.exc_info())
        out_gpstime = ts_output = False
    return out_gpstime, ts_output


def from_eitime(timestamp):
    """Convert a Google ei URL timestamp"""
    ts_type, reason, _, tz_out = ts_types["eitime"]
    try:
        urlsafe_chars = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_"
        )
        if not all(char in urlsafe_chars for char in timestamp):
            in_eitime = indiv_output = combined_output = False
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
                indiv_output = str(f"{ts_type}:\t\t\t{in_eitime}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_eitime} {tz_out}{__clr__}"
                )
            except base64.binascii.Error:
                in_eitime = indiv_output = combined_output = False
    except Exception:
        handle(sys.exc_info())
        in_eitime = indiv_output = combined_output = False
    return in_eitime, indiv_output, combined_output, reason, tz_out


def to_eitime(dt_val):
    """Try to convert a value to an ei URL timestamp"""
    ts_type, _, _, _ = ts_types["eitime"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[1970]).total_seconds() + int(dt_tz))
        unix_hex = struct.pack("<L", unix_time)
        urlsafe_encode = base64.urlsafe_b64encode(unix_hex)
        out_eitime = urlsafe_encode.decode(encoding="UTF-8").strip("=")
        ts_output = str(f"{ts_type}:\t\t\t{out_eitime}")
    except Exception:
        handle(sys.exc_info())
        out_eitime = ts_output = False
    return out_eitime, ts_output


def to_bplist(dt_val):
    """Convert a date to a Binary Plist timestamp"""
    ts_type, _, _, _ = ts_types["bplist"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_bplist = str(int((dt_obj - epochs[2001]).total_seconds()) - int(dt_tz))
        if int(out_bplist) < 0:
            out_bplist = "[!] Timestamp Boundary Exceeded [!]"
        ts_output = str(f"{ts_type}:\t{out_bplist}")
    except Exception:
        handle(sys.exc_info())
        out_bplist = ts_output = False
    return out_bplist, ts_output


def from_gsm(timestamp):
    """Convert a GSM timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["gsm"]
    try:
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
        tz_check = timestamp[12:14][::-1].lower()
        if (
            not len(timestamp) == 14
            or not all(char in hexdigits for char in timestamp)
            or tz_check not in tz_in_range
        ):
            in_gsm = indiv_output = combined_output = False
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
            indiv_output = str(f"{ts_type}: {in_gsm}")
            combined_output = str(f"{__red__}{ts_type}:\t\t\t{in_gsm}{__clr__}")
    except ValueError:
        in_gsm = indiv_output = combined_output = False
    except Exception:
        handle(sys.exc_info())
        in_gsm = indiv_output = combined_output = False
    return in_gsm, indiv_output, combined_output, reason, tz_out


def to_gsm(dt_val):
    """Convert a timestamp to a GSM timestamp"""
    ts_type, _, _, _ = ts_types["gsm"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
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
        ts_output = str(f"{ts_type}:\t\t\t{out_gsm}")
    except Exception:
        handle(sys.exc_info())
        out_gsm = ts_output = False
    return out_gsm, ts_output


def from_vm(timestamp):
    """Convert from a .vmsd createTimeHigh/createTimeLow timestamp"""
    ts_type, reason, _, tz_out = ts_types["vm"]
    try:
        if "," not in timestamp:
            in_vm = indiv_output = combined_output = False
        else:
            create_time_high = int(timestamp.split(",")[0])
            create_time_low = int(timestamp.split(",")[1])
            vmsd = (
                float(
                    (create_time_high * 2**32)
                    + struct.unpack("I", struct.pack("i", create_time_low))[0]
                )
                / 1000000
            )
            if vmsd >= 32536799999:
                in_vm = indiv_output = combined_output = False
            else:
                in_vm = dt.fromtimestamp(vmsd, timezone.utc).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_vm}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_vm} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_vm = indiv_output = combined_output = False
    return in_vm, indiv_output, combined_output, reason, tz_out


def to_vm(dt_val):
    """Convert date to a .vmsd createTime* value"""
    ts_type, _, _, _ = ts_types["vm"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_seconds = (
            int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000
        )
        create_time_high = int(float(unix_seconds) / 2**32)
        unpacked_int = unix_seconds - (create_time_high * 2**32)
        create_time_low = struct.unpack("i", struct.pack("I", unpacked_int))[0]
        out_vm = f"{str(create_time_high)},{str(create_time_low)}"
        ts_output = str(f"{ts_type}:\t\t\t{out_vm}")
    except Exception:
        handle(sys.exc_info())
        out_vm = ts_output = False
    return out_vm, ts_output


def from_tiktok(timestamp):
    """Convert a TikTok URL value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["tiktok"]
    try:
        if len(str(timestamp)) < 19 or not timestamp.isdigit():
            in_tiktok = indiv_output = combined_output = False
        else:
            unix_ts = int(timestamp) >> 32
            if unix_ts >= 32536799999:
                in_tiktok = indiv_output = combined_output = False
            else:
                in_tiktok = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                    __fmt__
                )
            indiv_output = str(f"{ts_type}: {in_tiktok}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_tiktok} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_tiktok = indiv_output = combined_output = False
    return in_tiktok, indiv_output, combined_output, reason, tz_out


def from_twitter(timestamp):
    """Convert a Twitter URL value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["twitter"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_twitter = indiv_output = combined_output = False
        else:
            unix_ts = (int(timestamp) >> 22) + 1288834974657
            if unix_ts >= 32536799999:
                in_twitter = indiv_output = combined_output = False
            else:
                in_twitter = dt.fromtimestamp(
                    float(unix_ts) / 1000.0, timezone.utc
                ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_twitter}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_twitter} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_twitter = indiv_output = combined_output = False
    return in_twitter, indiv_output, combined_output, reason, tz_out


def from_discord(timestamp):
    """Convert a Discord URL value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["discord"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_discord = indiv_output = combined_output = False
        else:
            unix_ts = (int(timestamp) >> 22) + 1420070400000
            if unix_ts >= 32536799999:
                in_discord = indiv_output = combined_output = False
            else:
                in_discord = dt.fromtimestamp(
                    float(unix_ts) / 1000.0, timezone.utc
                ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_discord}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_discord} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_discord = indiv_output = combined_output = False
    return in_discord, indiv_output, combined_output, reason, tz_out


def from_ksalnum(timestamp):
    """Extract a timestamp from a KSUID alpha-numeric value"""
    ts_type, reason, _, tz_out = ts_types["ksalnum"]
    try:
        ksalnum_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        if len(str(timestamp)) != 27 or not all(
            char in ksalnum_chars for char in timestamp
        ):
            in_ksalnum = indiv_output = combined_output = False
        else:
            length, i, variation = len(timestamp), 0, 0
            b_array = bytearray()
            for val in timestamp:
                variation += ksalnum_chars.index(val) * (62 ** (length - (i + 1)))
                i += 1
            while variation > 0:
                b_array.append(variation & 0xFF)
                variation //= 256
            b_array.reverse()
            ts_bytes = bytes(b_array)[0:4]
            unix_ts = int.from_bytes(ts_bytes, "big", signed=False) + 1400000000
            in_ksalnum = dt.fromtimestamp(float(unix_ts), timezone.utc).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_ksalnum}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_ksalnum} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_ksalnum = indiv_output = combined_output = False
    return in_ksalnum, indiv_output, combined_output, reason, tz_out


def from_mastodon(timestamp):
    """Convert a Mastodon value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["mastodon"]
    try:
        if len(str(timestamp)) < 18 or not timestamp.isdigit():
            in_mastodon = indiv_output = combined_output = False
        else:
            ts_conversion = int(timestamp) >> 16
            unix_ts = float(ts_conversion) / 1000.0
            if int(unix_ts) >= 32536799999:
                in_mastodon = indiv_output = combined_output = False
            else:
                in_mastodon = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_mastodon}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_mastodon} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_mastodon = indiv_output = combined_output = False
    return in_mastodon, indiv_output, combined_output, reason, tz_out


def to_mastodon(dt_val):
    """Convert a date/time to a Mastodon value"""
    ts_type, _, _, _ = ts_types["mastodon"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_seconds = int((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000
        bit_shift = unix_seconds << 16
        out_mastodon = f"{str(bit_shift)}"
        ts_output = str(f"{ts_type}:\t\t\t{out_mastodon}")
    except Exception:
        handle(sys.exc_info())
        out_mastodon = ts_output = False
    return out_mastodon, ts_output


def from_metasploit(timestamp):
    """Convert a Metasploit Payload UUID value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["metasploit"]
    try:
        urlsafe_chars = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890=-_"
        )
        meta_format = "8sBBBBBBBB"
        if len(str(timestamp)) < 22 or not all(
            char in urlsafe_chars for char in timestamp
        ):
            in_metasploit = indiv_output = combined_output = False
        else:
            b64decoded = base64.urlsafe_b64decode(timestamp[0:22] + "==")
            if len(b64decoded) < struct.calcsize(meta_format):
                raise Exception
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
            indiv_output = str(f"{ts_type}: {in_metasploit}")
            combined_output = str(
                f"{__red__}{ts_type}:\t{in_metasploit} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_metasploit = indiv_output = combined_output = False
    return in_metasploit, indiv_output, combined_output, reason, tz_out


def from_sony(timestamp):
    """Convert a Sonyflake value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["sony"]
    try:
        if len(str(timestamp)) != 15 or not all(
            char in hexdigits for char in timestamp
        ):
            in_sony = indiv_output = combined_output = False
        else:
            dec_value = int(timestamp, 16)
            ts_value = dec_value >> 24
            unix_ts = (ts_value + 140952960000) * 10
            in_sony = dt.fromtimestamp(float(unix_ts) / 1000.0, timezone.utc).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_sony}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_sony} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_sony = indiv_output = combined_output = False
    return in_sony, indiv_output, combined_output, reason, tz_out


def from_uuid(timestamp):
    """Convert a UUID value to date/time"""
    ts_type, reason, _, tz_out = ts_types["uuid"]
    try:
        uuid_lower = timestamp.lower()
        uuid_regex = re.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        )
        if not bool(uuid_regex.match(uuid_lower)):
            in_uuid = indiv_output = combined_output = False
        else:
            u_data = uuid.UUID(uuid_lower)
            if u_data.version == 1:
                unix_ts = int((u_data.time / 10000) - 12219292800000)
                in_uuid = dt.fromtimestamp(
                    float(unix_ts) / 1000.0, timezone.utc
                ).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_uuid}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_uuid} {tz_out}{__clr__}"
                )
            else:
                in_uuid = indiv_output = combined_output = False
    except Exception:
        handle(sys.exc_info())
        in_uuid = indiv_output = combined_output = False
    return in_uuid, indiv_output, combined_output, reason, tz_out


def from_dhcp6(timestamp):
    """Convert a DHCPv6 DUID value to date/time"""
    ts_type, reason, _, tz_out = ts_types["dhcp6"]
    try:
        if len(str(timestamp)) < 28 or not all(char in hexdigits for char in timestamp):
            in_dhcp6 = indiv_output = combined_output = False
        else:
            dhcp6_bytes = timestamp[8:16]
            dhcp6_dec = int(dhcp6_bytes, 16)
            dhcp6_ts = epochs[2000] + timedelta(seconds=int(dhcp6_dec))
            in_dhcp6 = dhcp6_ts.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_dhcp6}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_dhcp6} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_dhcp6 = indiv_output = combined_output = False
    return in_dhcp6, indiv_output, combined_output, reason, tz_out


def to_dhcp6(dt_val):
    """Convert a timestamp to a DHCP DUID value"""
    ts_type, _, _, _ = ts_types["dhcp6"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_time = int((dt_obj - epochs[2000]).total_seconds() - int(dt_tz))
        if int(unix_time) < 0:
            out_dhcp6 = "[!] Timestamp Boundary Exceeded [!]"
            ts_output = str(f"{ts_type}:\t\t{out_dhcp6}")
        else:
            out_dhcp6 = str(struct.pack(">L", unix_time).hex())
            ts_output = str(f"{ts_type}:\t\t00010001{out_dhcp6}000000000000")
    except Exception:
        handle(sys.exc_info())
        out_dhcp6 = ts_output = False
    return out_dhcp6, ts_output


def from_dotnet(timestamp):
    """Convert a .NET DateTime value to date/time"""
    ts_type, reason, _, tz_out = ts_types["dotnet"]
    try:
        if len(str(timestamp)) != 18 or not (timestamp).isdigit():
            in_dotnet = indiv_output = combined_output = False
        else:
            dotnet_offset = int((epochs[1970] - epochs[1]).total_seconds()) * 10000000
            dotnet_to_umil = (int(timestamp) - dotnet_offset) / 10000000
            if dotnet_to_umil < 0:
                in_dotnet = indiv_output = combined_output = False
            else:
                in_dotnet = dt.fromtimestamp(dotnet_to_umil, timezone.utc).strftime(
                    __fmt__
                )
            indiv_output = str(f"{ts_type}: {in_dotnet} {tz_out}")
            combined_output = str(f"{__red__}{ts_type}:\t{in_dotnet} {tz_out}{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_dotnet = indiv_output = combined_output = False
    return in_dotnet, indiv_output, combined_output, reason, tz_out


def to_dotnet(dt_val):
    """Convert date to a .NET DateTime value"""
    ts_type, _, _, _ = ts_types["dotnet"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        out_dotnet = str(
            int(((dt_obj - epochs[1]).total_seconds() - int(dt_tz)) * 10000000)
        )
        ts_output = str(f"{ts_type}:\t{out_dotnet}")
    except Exception:
        handle(sys.exc_info())
        out_dotnet = ts_output = False
    return out_dotnet, ts_output


def from_gbound(timestamp):
    """Convert a GMail Boundary value to date/time"""
    ts_type, reason, _, tz_out = ts_types["gbound"]
    try:
        if len(str(timestamp)) != 28 or not all(
            char in hexdigits for char in timestamp
        ):
            in_gbound = indiv_output = combined_output = False
        else:
            working_value = timestamp[12:26]
            end = working_value[:6]
            begin = working_value[6:14]
            full_dec = int("".join(begin + end), 16)
            in_gbound = dt.fromtimestamp(full_dec / 1000000, timezone.utc).strftime(
                __fmt__
            )
            indiv_output = str(f"{ts_type}: {in_gbound} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_gbound} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_gbound = indiv_output = combined_output = False
    return in_gbound, indiv_output, combined_output, reason, tz_out


def to_gbound(dt_val):
    """Convert date to a GMail Boundary value"""
    ts_type, _, _, _ = ts_types["gbound"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        to_int = int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000)
        if len(f"{to_int:x}") < 14:
            to_int = f"0{to_int:x}"
        begin = to_int[8:]
        end = to_int[:8]
        out_gbound = f"000000000000{begin}{end}00"
        ts_output = str(f"{ts_type}:\t\t{out_gbound}")
    except Exception:
        handle(sys.exc_info())
        out_gbound = ts_output = False
    return out_gbound, ts_output


def from_gmsgid(timestamp):
    """Convert a GMail Message ID to a date/time value"""
    ts_type, reason, _, tz_out = ts_types["gmsgid"]
    try:
        gmsgid = timestamp
        if str(gmsgid).isdigit() and len(str(gmsgid)) == 19:
            gmsgid = str(f"{int(gmsgid):x}")
        if len(str(gmsgid)) != 16 or not all(char in hexdigits for char in gmsgid):
            in_gmsgid = indiv_output = combined_output = False
        else:
            working_value = gmsgid[:11]
            to_int = int(working_value, 16)
            in_gmsgid = dt.fromtimestamp(to_int / 1000, timezone.utc).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_gmsgid} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_gmsgid} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_gmsgid = indiv_output = combined_output = False
    return in_gmsgid, indiv_output, combined_output, reason, tz_out


def to_gmsgid(dt_val):
    """Convert date to a GMail Message ID value"""
    ts_type, _, _, _ = ts_types["gmsgid"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        to_int = int(((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000)
        ts_hex = f"{to_int:x}"
        out_gmsgid = f"{ts_hex}00000"
        ts_output = str(f"{ts_type}:\t\t{out_gmsgid}")
    except Exception:
        handle(sys.exc_info())
        out_gmsgid = ts_output = False
    return out_gmsgid, ts_output


def from_moto(timestamp):
    """Convert a Motorola 6-byte hex timestamp to a date"""
    ts_type, reason, _, tz_out = ts_types["moto"]
    try:
        if len(str(timestamp)) != 12 or not all(
            char in hexdigits for char in timestamp
        ):
            in_moto = indiv_output = combined_output = False
        else:
            hex_to_dec = [
                int(timestamp[i : i + 2], 16) for i in range(0, len(timestamp), 2)
            ]
            hex_to_dec[0] = hex_to_dec[0] + 1970
            if hex_to_dec[1] not in range(1, 13):
                in_moto = indiv_output = combined_output = False
            else:
                dt_obj = dt(
                    hex_to_dec[0],
                    hex_to_dec[1],
                    hex_to_dec[2],
                    hex_to_dec[3],
                    hex_to_dec[4],
                    hex_to_dec[5],
                )
                in_moto = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_moto}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_moto} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_moto = indiv_output = combined_output = False
    return in_moto, indiv_output, combined_output, reason, tz_out


def to_moto(dt_val):
    """Convert a date to Motorola's 6-byte hex timestamp"""
    ts_type, _, _, _ = ts_types["moto"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = str(f"{ts_type}:\t\t\t{out_moto}")
    except Exception:
        handle(sys.exc_info())
        out_moto = ts_output = False
    return out_moto, ts_output


def from_nokia(timestamp):
    """Convert a Nokia 4-byte value to date/time"""
    ts_type, reason, _, tz_out = ts_types["nokia"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_nokia = indiv_output = combined_output = False
        else:
            to_int = int(timestamp, 16)
            int_diff = to_int ^ 4294967295
            int_diff = ~int_diff + 1
            unix_ts = int_diff + (epochs[2050] - epochs[1970]).total_seconds()
            if unix_ts < 0:
                in_nokia = indiv_output = combined_output = False
            else:
                in_nokia = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_nokia}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_nokia} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_nokia = indiv_output = combined_output = False
    return in_nokia, indiv_output, combined_output, reason, tz_out


def to_nokia(dt_val):
    """Convert a date/time value to a Nokia 4-byte timestamp"""
    ts_type, _, _, _ = ts_types["nokia"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_ts = (dt_obj - epochs[1970]).total_seconds() - int(dt_tz)
        int_diff = int(unix_ts - (epochs[2050] - epochs[1970]).total_seconds())
        int_diff = int_diff - 1
        dec_value = ~int_diff ^ 4294967295
        out_nokia = f"{dec_value:x}"
        ts_output = str(f"{ts_type}:\t\t\t{out_nokia}")
    except Exception:
        handle(sys.exc_info())
        out_nokia = ts_output = False
    return out_nokia, ts_output


def from_nokiale(timestamp):
    """Convert a little-endian Nokia 4-byte value to date/time"""
    ts_type, reason, _, tz_out = ts_types["nokiale"]
    try:
        if not len(timestamp) == 8 or not all(char in hexdigits for char in timestamp):
            in_nokiale = indiv_output = combined_output = False
        else:
            to_be = "".join(
                [timestamp[i : i + 2] for i in range(0, len(timestamp), 2)][::-1]
            )
            to_int = int(to_be, 16)
            int_diff = to_int ^ 4294967295
            int_diff = ~int_diff + 1
            unix_ts = int_diff + (epochs[2050] - epochs[1970]).total_seconds()
            if unix_ts < 0:
                in_nokiale = indiv_output = combined_output = False
            else:
                in_nokiale = dt.fromtimestamp(unix_ts, timezone.utc).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_nokiale}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t\t{in_nokiale} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_nokiale = indiv_output = combined_output = False
    return in_nokiale, indiv_output, combined_output, reason, tz_out


def to_nokiale(dt_val):
    """Convert a date/time value to a little-endian Nokia 4-byte timestamp"""
    ts_type, _, _, _ = ts_types["nokiale"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_ts = (dt_obj - epochs[1970]).total_seconds() - int(dt_tz)
        int_diff = int(unix_ts - (epochs[2050] - epochs[1970]).total_seconds())
        int_diff = int_diff - 1
        dec_val = ~int_diff ^ 4294967295
        hex_val = f"{dec_val:x}"
        out_nokiale = "".join(
            [hex_val[i : i + 2] for i in range(0, len(hex_val), 2)][::-1]
        )
        ts_output = str(f"{ts_type}:\t\t\t{out_nokiale}")
    except Exception:
        handle(sys.exc_info())
        out_nokiale = ts_output = False
    return out_nokiale, ts_output


def from_ns40(timestamp):
    """Convert a Nokia S40 7-byte value to a time/time"""
    ts_type, reason, _, tz_out = ts_types["ns40"]
    try:
        if not len(timestamp) == 14 or not all(char in hexdigits for char in timestamp):
            in_ns40 = indiv_output = combined_output = False
        else:
            ns40 = timestamp
            ns40_val = {"yr": ns40[:4], "mon": ns40[4:6], "day": ns40[6:8], "hr": ns40[8:10], "min": ns40[10:12], "sec": ns40[12:] }
            for each_key, _ in ns40_val.items():
                ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
            if ns40_val["yr"] > 9999:
                in_ns40 = indiv_output = combined_output = False
            elif (int(ns40_val["mon"]) > 12) or (int(ns40_val["mon"] < 1)):
                in_ns40 = indiv_output = combined_output = False
            else:
                in_ns40 = dt(
                    ns40_val["yr"],
                    ns40_val["mon"],
                    ns40_val["day"],
                    ns40_val["hr"],
                    ns40_val["min"],
                    ns40_val["sec"],
                ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ns40}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_ns40} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_ns40 = indiv_output = combined_output = False
    return in_ns40, indiv_output, combined_output, reason, tz_out


def to_ns40(dt_val):
    """Convert a date/time value to a Nokia S40 7-byte timestamp"""
    ts_type, _, _, _ = ts_types["ns40"]
    try:
        dt_obj = duparser.parse(dt_val)
        dt_tz = 0
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        dt_obj = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        dt_obj = dt.fromtimestamp(int(dt_obj), timezone.utc)
        hex_vals = []
        hex_vals.append(f"{dt_obj.year:x}".zfill(4))
        hex_vals.append(f"{dt_obj.month:x}".zfill(2))
        hex_vals.append(f"{dt_obj.day:x}".zfill(2))
        hex_vals.append(f"{dt_obj.hour:x}".zfill(2))
        hex_vals.append(f"{dt_obj.minute:x}".zfill(2))
        hex_vals.append(f"{dt_obj.second:x}".zfill(2))
        out_ns40 = "".join(hex_vals)
        ts_output = str(f"{ts_type}:\t\t\t{out_ns40}")
    except Exception:
        handle(sys.exc_info())
        out_ns40 = ts_output = False
    return out_ns40, ts_output


def from_ns40le(timestamp):
    """Convert a little-endian Nokia S40 7-byte value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["ns40le"]
    try:
        if len(str(timestamp)) != 14 or not all(
            char in hexdigits for char in timestamp
        ):
            in_ns40le = indiv_output = combined_output = False
        else:
            ns40le = timestamp
            ns40_val = {"yr": "".join([ns40le[i : i + 2] for i in range(0, len(ns40le[:4]), 2)][::-1]), "mon": ns40le[4:6], "day": ns40le[6:8], "hr": ns40le[8:10], "min": ns40le[10:12], "sec": ns40le[12:] }
            for each_key, _ in ns40_val.items():
                ns40_val[str(each_key)] = int(ns40_val[str(each_key)], 16)
            if ns40_val["yr"] > 9999:
                in_ns40le = indiv_output = combined_output = False
            elif (int(ns40_val["mon"]) > 12) or (int(ns40_val["mon"] < 1)):
                in_ns40le = indiv_output = combined_output = False
            else:
                in_ns40le = dt(
                    ns40_val["yr"],
                    ns40_val["mon"],
                    ns40_val["day"],
                    ns40_val["hr"],
                    ns40_val["min"],
                    ns40_val["sec"],
                ).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ns40le}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_ns40le} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_ns40le = indiv_output = combined_output = False
    return in_ns40le, indiv_output, combined_output, reason, tz_out


def to_ns40le(dt_val):
    """Convert a date/time value to a little-endian Nokia S40 7-byte timestamp"""
    ts_type, _, _, _ = ts_types["ns40le"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        dt_obj = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        dt_obj = dt.fromtimestamp(int(dt_obj), timezone.utc)
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
        ts_output = str(f"{ts_type}:\t\t{out_ns40le}")
    except Exception:
        handle(sys.exc_info())
        out_ns40le = ts_output = False
    return out_ns40le, ts_output


def from_bitdec(timestamp):
    """Convert a 10-digit Bitwise Decimal value to a date/time"""
    ts_type, reason, _, tz_out = ts_types["bitdec"]
    try:
        if len(str(timestamp)) != 10 or not (timestamp).isdigit():
            in_bitdec = indiv_output = combined_output = False
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
                in_bitdec = indiv_output = combined_output = False
            indiv_output = str(f"{ts_type}: {in_bitdec} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_bitdec} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_bitdec = indiv_output = combined_output = False
    return in_bitdec, indiv_output, combined_output, reason, tz_out


def to_bitdec(dt_val):
    """Convert a date/time value to a Bitwise Decimal timestamp"""
    ts_type, _, _, _ = ts_types["bitdec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        dt_obj = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        dt_obj = dt.fromtimestamp(int(dt_obj), timezone.utc)
        out_bitdec = str(
            (dt_obj.year << 20)
            + (dt_obj.month << 16)
            + (dt_obj.day << 11)
            + (dt_obj.hour << 6)
            + (dt_obj.minute)
        )
        ts_output = str(f"{ts_type}:\t\t{out_bitdec}")
    except Exception:
        handle(sys.exc_info())
        out_bitdec = ts_output = False
    return out_bitdec, ts_output


def from_bitdate(timestamp):
    """Convert a Samsung/LG 4-byte hex timestamp to a date/time"""
    ts_type, reason, _, tz_out = ts_types["bitdate"]
    try:
        if len(str(timestamp)) != 8 or not all(char in hexdigits for char in timestamp):
            in_bitdate = indiv_output = combined_output = False
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
            try:
                in_bitdate = dt(
                    bitdate_yr, bitdate_mon, bitdate_day, bitdate_hr, bitdate_min
                ).strftime(__fmt__)
            except ValueError:
                in_bitdate = indiv_output = combined_output = False
            indiv_output = str(f"{ts_type}: {in_bitdate} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_bitdate} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_bitdate = indiv_output = combined_output = False
    return in_bitdate, indiv_output, combined_output, reason, tz_out


def to_bitdate(dt_val):
    """Convert a date/time value to a Samsung/LG timestamp"""
    ts_type, _, _, _ = ts_types["bitdate"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = str(f"{ts_type}:\t\t\t{out_bitdate}")
    except Exception:
        handle(sys.exc_info())
        out_bitdate = ts_output = False
    return out_bitdate, ts_output


def from_ksdec(timestamp):
    """Convert a KSUID decimal value to a date"""
    ts_type, reason, _, tz_out = ts_types["ksdec"]
    try:
        if len(timestamp) != 9 or not timestamp.isdigit():
            in_ksdec = indiv_output = combined_output = False
        else:
            ts_val = int(timestamp) + int(epochs["kstime"])
            in_ksdec = dt.fromtimestamp(float(ts_val), timezone.utc).strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_ksdec} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t\t{in_ksdec} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_ksdec = indiv_output = combined_output = False
    return in_ksdec, indiv_output, combined_output, reason, tz_out


def to_ksdec(dt_val):
    """Convert date to a KSUID decimal value"""
    ts_type, _, _, _ = ts_types["ksdec"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_ts = str(int((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz))
        out_ksdec = str(int(unix_ts) - int(epochs["kstime"]))
        if int(out_ksdec) < 0:
            out_ksdec = "[!] Timestamp Boundary Exceeded [!]"
        ts_output = str(f"{ts_type}:\t\t\t{out_ksdec}")
    except Exception:
        handle(sys.exc_info())
        out_ksdec = ts_output = False
    return out_ksdec, ts_output


def from_biomehex(timestamp):
    """Convert an Apple Biome Hex value to a date - from Little Endian"""
    ts_type, reason, _, tz_out = ts_types["biomehex"]
    try:
        biomehex = str(timestamp)
        if len(biomehex) != 16 or not all(char in hexdigits for char in biomehex):
            in_biomehex = indiv_output = combined_output = False
        else:
            if biomehex[:2] == "41":
                biomehex = "".join(
                    [biomehex[i : i + 2] for i in range(0, len(biomehex), 2)][::-1]
                )
            byte_val = bytes.fromhex(str(biomehex))
            nsdate_val = struct.unpack("<d", byte_val)[0]
            if nsdate_val >= 1e17:
                in_biomehex = indiv_output = combined_output = False
            else:
                dt_obj = epochs[2001] + timedelta(seconds=float(nsdate_val))
                in_biomehex = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_biomehex} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_biomehex} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_biomehex = indiv_output = combined_output = False
    return in_biomehex, indiv_output, combined_output, reason, tz_out


def to_biomehex(dt_val):
    """Convert a date/time to an Apple Biome Hex value"""
    ts_type, _, _, _ = ts_types["biomehex"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        bplist_stamp = str(float((dt_obj - epochs[2001]).total_seconds()) - int(dt_tz))
        byte_biome = struct.pack(">d", float(bplist_stamp))
        out_biomehex = bytes.hex(byte_biome)
        ts_output = str(f"{ts_type}:\t\t{out_biomehex}")
    except Exception:
        handle(sys.exc_info())
        out_biomehex = ts_output = False
    return out_biomehex, ts_output


def from_biome64(timestamp):
    """Convert a 64-bit decimal value to a date/time value"""
    ts_type, reason, _, tz_out = ts_types["biome64"]
    try:
        if len(timestamp) != 19 or not timestamp.isdigit():
            in_biome64 = indiv_output = combined_output = False
        else:
            nsdate_unpacked = int(
                struct.unpack("<d", int(timestamp).to_bytes(8, "little"))[0]
            )
            if nsdate_unpacked >= 1e17:
                in_biome64 = indiv_output = combined_output = False
            else:
                dt_obj = epochs[2001] + timedelta(seconds=float(nsdate_unpacked))
                in_biome64 = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_biome64} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t{in_biome64} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_biome64 = indiv_output = combined_output = False
    return in_biome64, indiv_output, combined_output, reason, tz_out


def to_biome64(dt_val):
    """Convert a date/time value to a"""
    ts_type, _, _, _ = ts_types["biome64"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        nsdate_stamp = float((dt_obj - epochs[2001]).total_seconds()) - int(dt_tz)
        out_biome64 = str(int.from_bytes(struct.pack(">d", nsdate_stamp), "big"))
        ts_output = str(f"{ts_type}:\t{out_biome64}")
    except Exception:
        handle(sys.exc_info())
        out_biome64 = ts_output = False
    return out_biome64, ts_output


def from_s32(timestamp):
    """
    Convert an S32 timestamp to a date/time value
    Since BlueSky is not yet in use, this function is essentially a beta
    """
    ts_type, reason, _, tz_out = ts_types["s32"]
    try:
        result = 0
        timestamp = str(timestamp)
        if len(timestamp) != 9 or not all(char in S32_CHARS for char in timestamp):
            in_s32 = indiv_output = combined_output = False
        else:
            for char in timestamp:
                result = result * 32 + S32_CHARS.index(char)
            dt_obj = dt.fromtimestamp(result / 1000.0, timezone.utc)
            in_s32 = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_s32} {tz_out}")
            combined_output = str(f"{__red__}{ts_type}:\t\t{in_s32} {tz_out}{__clr__}")
    except Exception:
        handle(sys.exc_info())
        in_s32 = indiv_output = combined_output = False
    return in_s32, indiv_output, combined_output, reason, tz_out


def to_s32(dt_val):
    """
    Convert a date/time to an S32-encoded timestamp
    Since BlueSky is not yet in use, this function is essentially a beta
    """
    ts_type, _, _, _ = ts_types["s32"]
    try:
        result = ""
        index = 0
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_mil = int(((dt_obj - epochs[1970]).total_seconds()) - int(dt_tz)) * 1000
        while unix_mil:
            index = unix_mil % 32
            unix_mil = math.floor(unix_mil / 32)
            result = S32_CHARS[index] + result
        out_s32 = result
        ts_output = str(f"{ts_type}:\t{out_s32}")
    except Exception:
        handle(sys.exc_info())
        out_s32 = ts_output = False
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
            in_apache = indiv_output = combined_output = False
        else:
            dec_val = int(timestamp, 16)
            dt_obj = epochs[1970] + timedelta(microseconds=dec_val)
            in_apache = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_apache} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_apache} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_apache = indiv_output = combined_output = False
    return in_apache, indiv_output, combined_output, reason, tz_out


def to_apache(dt_val):
    """Convert a date/time to an Apache cookie value"""
    ts_type, _, _, _ = ts_types["apache"]
    try:
        dt_obj = duparser.parse(dt_val)
        if hasattr(dt_obj.tzinfo, "_offset"):
            dt_tz = dt_obj.tzinfo._offset.total_seconds()
        else:
            dt_tz = 0
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        apache_int = int(
            ((dt_obj - epochs[1970]).total_seconds() - int(dt_tz)) * 1000000
        )
        out_apache = f"{apache_int:x}"
        ts_output = str(f"{ts_type}:\t\t{out_apache}")
    except Exception:
        handle(sys.exc_info())
        out_apache = ts_output = False
    return out_apache, ts_output


def from_leb128_hex(timestamp):
    """Convert a LEB 128 hex value to a date"""
    ts_type, reason, _, tz_out = ts_types["leb128_hex"]
    try:
        if not len(timestamp) % 2 == 0 or not all(
            char in hexdigits for char in timestamp
        ):
            in_leb128_hex = indiv_output = combined_output = False
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
            in_leb128_hex, _, _, _, _ = from_unix_milli(str(unix_milli))
            indiv_output = str(f"{ts_type}: {in_leb128_hex} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t\t{in_leb128_hex} {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_leb128_hex = indiv_output = combined_output = False
    return in_leb128_hex, indiv_output, combined_output, reason, tz_out


def to_leb128_hex(dt_val):
    """Convert a date to a LEB128 hex value."""
    ts_type, _, _, _ = ts_types["leb128_hex"]
    try:
        dt_obj = duparser.parse(dt_val, ignoretz=True)
        unix_milli, _ = to_unix_milli(str(dt_obj))
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
        ts_output = str(f"{ts_type}:\t\t{out_leb128_hex}")
    except Exception:
        handle(sys.exc_info())
        out_leb128_hex = ts_output = False
    return out_leb128_hex, ts_output


def from_julian_dec(timestamp):
    """Convert Julian Date decimal value to a date"""
    ts_type, reason, _, tz_out = ts_types["julian_dec"]
    try:
        if (
            "." not in timestamp
            or not (
                (len(timestamp.split(".")[0]) == 7)
                and (len(timestamp.split(".")[1]) in range(0, 11))
            )
            or not "".join(timestamp.split(".")).isdigit()
        ):
            in_julian_dec = indiv_output = combined_output = False
        else:
            try:
                timestamp = float(timestamp)
            except Exception:
                timestamp = int(timestamp)

            yr, mon, day, hr, mins, sec, mil = jd.to_gregorian(timestamp)
            dt_vals = [yr, mon, day, hr, mins, sec, mil]
            if any(val < 0 for val in dt_vals):
                in_julian_dec = indiv_output = combined_output = False
            else:
                in_julian_dec = (dt(yr, mon, day, hr, mins, sec, mil)).strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_julian_dec} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_julian_dec} {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_julian_dec = indiv_output = combined_output = False
    return in_julian_dec, indiv_output, combined_output, reason, tz_out


def to_julian_dec(dt_val):
    """Convert a date to a Julian Date"""
    ts_type, _, _, _ = ts_types["julian_dec"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = f"{ts_type}:\t{out_julian_dec}"
    except Exception:
        handle(sys.exc_info())
        out_julian_dec = ts_output = False
    return out_julian_dec, ts_output


def from_julian_hex(timestamp):
    """Convert Julian Date hex value to a date"""
    ts_type, reason, _, tz_out = ts_types["julian_hex"]
    try:
        if not len(timestamp) // 2 == 7 or not all(
            char in hexdigits for char in timestamp
        ):
            in_julian_hex = indiv_output = combined_output = False
        else:
            julianday = int(timestamp[:6], 16)
            julianmil = int(timestamp[6:], 16)
            julianmil = julianmil / 10 ** int((len(str(julianmil))))
            julian_date = int(julianday) + int(julianmil)
            yr, mon, day, hr, mins, sec, mil = jd.to_gregorian(julian_date)
            dt_vals = [yr, mon, day, hr, mins, sec, mil]
            if yr > 3000 or any(val < 0 for val in dt_vals):
                in_julian_hex = indiv_output = combined_output = False
            else:
                dt_obj = dt(yr, mon, day, hr, mins, sec, mil)
                in_julian_hex = dt_obj.strftime(__fmt__)
                indiv_output = str(f"{ts_type}: {in_julian_hex} {tz_out}")
                combined_output = str(
                    f"{__red__}{ts_type}:\t\t{in_julian_hex}" f" {tz_out}{__clr__}"
                )
    except Exception:
        handle(sys.exc_info())
        in_julian_hex = indiv_output = combined_output = False
    return in_julian_hex, indiv_output, combined_output, reason, tz_out


def to_julian_hex(dt_val):
    """Convert a date to a Julian Hex Date"""
    ts_type, _, _, _ = ts_types["julian_hex"]
    try:
        dt_obj = duparser.parse(dt_val)
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
        ts_output = str(f"{ts_type}:\t\t{out_julian_hex}")
    except Exception:
        handle(sys.exc_info())
        out_julian_hex = ts_output = False
    return out_julian_hex, ts_output


def from_semi_octet(timestamp):
    """Convert from a Semi-Octet decimal value to a date"""
    ts_type, reason, _, tz_out = ts_types["semi_octet"]
    try:
        yr = mon = day = hr = mins = sec = None
        if (
            len(str(timestamp)) != 12
            or len(str(timestamp)) != 14
            and not str(timestamp).isdigit()
        ):
            in_semi_octet = indiv_output = combined_output = False
        else:
            if len(str(timestamp)) == 12:
                yr, mon, day, hr, mins, sec = [
                    (a + b)[::-1] for a, b in zip(timestamp[::2], timestamp[1::2])
                ]
            elif len(str(timestamp)) == 14:
                yr, mon, day, hr, mins, sec, _ = [
                    (a + b)[::-1] for a, b in zip(timestamp[::2], timestamp[1::2])
                ]
            dt_obj = dt(
                int(yr) + 2000, int(mon), int(day), int(hr), int(mins), int(sec)
            )
            in_semi_octet = dt_obj.strftime(__fmt__)
            indiv_output = str(f"{ts_type}: {in_semi_octet} {tz_out}")
            combined_output = str(
                f"{__red__}{ts_type}:\t{in_semi_octet}" f" {tz_out}{__clr__}"
            )
    except Exception:
        handle(sys.exc_info())
        in_semi_octet = indiv_output = combined_output = False
    return in_semi_octet, indiv_output, combined_output, reason, tz_out


def to_semi_octet(dt_val):
    """Convert a date to a Semi-Octet decimal value"""
    ts_type, _, _, _ = ts_types["semi_octet"]
    try:
        swap_list = []
        dt_obj = duparser.parse(dt_val)
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
        ts_output = f"{ts_type}:\t{out_semi_octet}"
    except Exception:
        handle(sys.exc_info())
        out_semi_octet = ts_output = False
    return out_semi_octet, ts_output


def date_range(start, end, check_date):
    """Check if date is in range of start and end, return True if it is"""
    if start <= end:
        return start <= check_date <= end
    return start <= check_date or check_date <= end


def from_all(timestamps):
    """Output all processed timestamp values and find date from provided timestamp"""
    this_yr = int(dt.now().strftime("%Y"))
    full_list = {}
    for func in from_funcs:
        func_name = func.__name__.replace("from_", "")
        (result, _, combined_output, _, tz_out) = func(timestamps)
        if result and combined_output:
            if isinstance(result, str):
                if int(duparser.parse(result).strftime("%Y")) not in range(
                    this_yr - 5, this_yr + 5
                ):
                    combined_output = combined_output.strip(__red__).strip(__clr__)
            full_list[func_name] = [result, combined_output, tz_out]
    return full_list


def to_timestamps(dt_val):
    """Convert provided date to all timestamps"""
    results = {}
    ts_outputs = []
    for func in to_funcs:
        result, ts_output = func(dt_val)
        func_name = (func.__name__).replace("to_", "")
        if isinstance(result, str):
            results[func_name] = result
            ts_outputs.append(ts_output)
    return results, ts_outputs


single_funcs = {
    "unix": from_unix_sec,
    "umil": from_unix_milli,
    "umilhex": from_unix_milli_hex,
    "wh": from_windows_hex_64,
    "whle": from_windows_hex_64le,
    "chrome": from_chrome,
    "active": from_ad,
    "uhbe": from_unix_hex_32be,
    "uhle": from_unix_hex_32le,
    "cookie": from_cookie,
    "oleb": from_ole_be,
    "olel": from_ole_le,
    "nsdate": from_nsdate,
    "bplist": from_bplist,
    "iostime": from_iostime,
    "mac": from_mac,
    "hfsdec": from_hfs_dec,
    "hfsbe": from_hfs_be,
    "hfsle": from_hfs_le,
    "fat": from_fat,
    "msdos": from_msdos,
    "systime": from_systemtime,
    "ft": from_filetime,
    "hotmail": from_hotmail,
    "pr": from_prtime,
    "auto": from_ole_auto,
    "ms1904": from_ms1904,
    "sym": from_symtime,
    "gps": from_gpstime,
    "eitime": from_eitime,
    "gsm": from_gsm,
    "vm": from_vm,
    "tiktok": from_tiktok,
    "twitter": from_twitter,
    "discord": from_discord,
    "ksalnum": from_ksalnum,
    "mastodon": from_mastodon,
    "meta": from_metasploit,
    "sony": from_sony,
    "uu": from_uuid,
    "dhcp6": from_dhcp6,
    "dotnet": from_dotnet,
    "gbound": from_gbound,
    "gmsgid": from_gmsgid,
    "moto": from_moto,
    "nokia": from_nokia,
    "nokiale": from_nokiale,
    "ns40": from_ns40,
    "ns40le": from_ns40le,
    "bitdec": from_bitdec,
    "bitdate": from_bitdate,
    "ksdec": from_ksdec,
    "exfat": from_exfat,
    "biome64": from_biome64,
    "biomehex": from_biomehex,
    "s32": from_s32,
    "apache": from_apache,
    "leb128": from_leb128_hex,
    "jdec": from_julian_dec,
    "jhex": from_julian_hex,
    "semi": from_semi_octet,
}
from_funcs = [
    from_ad,
    from_apache,
    from_biome64,
    from_biomehex,
    from_bitdate,
    from_bitdec,
    from_dhcp6,
    from_discord,
    from_exfat,
    from_fat,
    from_gbound,
    from_gmsgid,
    from_chrome,
    from_eitime,
    from_gpstime,
    from_gsm,
    from_hfs_be,
    from_hfs_le,
    from_nsdate,
    from_julian_dec,
    from_julian_hex,
    from_ksalnum,
    from_ksdec,
    from_leb128_hex,
    from_hfs_dec,
    from_mastodon,
    from_metasploit,
    from_systemtime,
    from_filetime,
    from_hotmail,
    from_dotnet,
    from_moto,
    from_prtime,
    from_msdos,
    from_ms1904,
    from_ns40,
    from_ns40le,
    from_nokia,
    from_nokiale,
    from_ole_auto,
    from_s32,
    from_semi_octet,
    from_sony,
    from_symtime,
    from_tiktok,
    from_twitter,
    from_unix_hex_32be,
    from_unix_hex_32le,
    from_unix_sec,
    from_unix_milli,
    from_unix_milli_hex,
    from_uuid,
    from_vm,
    from_windows_hex_64,
    from_windows_hex_64le,
    from_cookie,
    from_ole_be,
    from_ole_le,
]
to_funcs = [
    to_ad,
    to_apache,
    to_biome64,
    to_biomehex,
    to_bitdate,
    to_bitdec,
    to_dhcp6,
    to_exfat,
    to_fat,
    to_gbound,
    to_gmsgid,
    to_chrome,
    to_eitime,
    to_gpstime,
    to_gsm,
    to_hfs_be,
    to_hfs_le,
    to_julian_dec,
    to_julian_hex,
    to_ksdec,
    to_leb128_hex,
    to_hfs_dec,
    to_mastodon,
    to_systemtime,
    to_filetime,
    to_hotmail,
    to_dotnet,
    to_moto,
    to_prtime,
    to_msdos,
    to_ms1904,
    to_ns40,
    to_ns40le,
    to_nokia,
    to_nokiale,
    to_bplist,
    to_iostime,
    to_mac,
    to_ole_auto,
    to_s32,
    to_semi_octet,
    to_symtime,
    to_unix_hex_32be,
    to_unix_hex_32le,
    to_unix_sec,
    to_unix_milli,
    to_unix_milli_hex,
    to_vm,
    to_windows_hex_64,
    to_windows_hex_64le,
    to_cookie,
    to_ole_be,
    to_ole_le,
]


def main():
    """Parse all passed arguments"""
    now = dt.now().strftime(__fmt__)
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
        "--active", metavar="", help="convert from Active Directory value"
    )
    arg_parse.add_argument(
        "--apache", metavar="", help="convert from an Apache Cookie hex value"
    )
    arg_parse.add_argument(
        "--auto", metavar="", help="convert from OLE Automation Date format"
    )
    arg_parse.add_argument(
        "--biome64", metavar="", help="convert from an Apple Biome 64-bit decimal"
    )
    arg_parse.add_argument(
        "--biomehex", metavar="", help="convert from an Apple Biome hex value"
    )
    arg_parse.add_argument(
        "--bitdate", metavar="", help="convert from a Samsung/LG 4-byte value"
    )
    arg_parse.add_argument(
        "--bitdec", metavar="", help="convert from a bitwise decimal 10-digit value"
    )
    arg_parse.add_argument(
        "--bplist", metavar="", help="convert from an iOS Binary Plist value"
    )
    arg_parse.add_argument(
        "--chrome", metavar="", help="convert from Google Chrome value"
    )
    arg_parse.add_argument(
        "--cookie", metavar="", help="convert from Windows Cookie Date (Low,High)"
    )
    arg_parse.add_argument(
        "--dhcp6", metavar="", help="convert from a DHCP6 DUID value"
    )
    arg_parse.add_argument(
        "--discord", metavar="", help="convert from a Discord URL value"
    )
    arg_parse.add_argument(
        "--dotnet", metavar="", help="convert from a .NET DateTime value"
    )
    arg_parse.add_argument(
        "--eitime", metavar="", help="convert from a Google EI URL value"
    )
    arg_parse.add_argument(
        "--exfat", metavar="", help="convert from an exFAT 4-byte value"
    )
    arg_parse.add_argument(
        "--fat", metavar="", help="convert from FAT Date + Time (wFat)"
    )
    arg_parse.add_argument("--ft", metavar="", help="convert from a FILETIME value")
    arg_parse.add_argument(
        "--gbound", metavar="", help="convert from a GMail Boundary value"
    )
    arg_parse.add_argument(
        "--gmsgid", metavar="", help="convert from a GMail Message ID value"
    )
    arg_parse.add_argument("--gps", metavar="", help="convert from a GPS value")
    arg_parse.add_argument("--gsm", metavar="", help="convert from a GSM value")
    arg_parse.add_argument(
        "--hfsbe", metavar="", help="convert from HFS(+) BE (HFS=Local, HFS+=UTC)"
    )
    arg_parse.add_argument(
        "--hfsle", metavar="", help="convert from HFS(+) LE (HFS=Local, HFS+=UTC)"
    )
    arg_parse.add_argument(
        "--hfsdec", metavar="", help="convert from a Mac OS/HFS+ Decimal value"
    )
    arg_parse.add_argument("--hotmail", metavar="", help="convert from a Hotmail value")
    arg_parse.add_argument("--iostime", metavar="", help="convert from an iOS 11 value")
    arg_parse.add_argument(
        "--jdec", metavar="", help="convert from a Julian Date decimal value"
    )
    arg_parse.add_argument(
        "--jhex", metavar="", help="convert from a Julian Date hex value"
    )
    arg_parse.add_argument(
        "--ksdec", metavar="", help="convert from a KSUID 9-digit value"
    )
    arg_parse.add_argument(
        "--ksalnum", metavar="", help="convert from a KSUID 27-character value"
    )
    arg_parse.add_argument(
        "--leb128", metavar="", help="convert from a LEB128 hex value"
    )
    arg_parse.add_argument("--mac", metavar="", help="convert from Mac Absolute Time")
    arg_parse.add_argument(
        "--mastodon", metavar="", help="convert from a Mastodon URL value"
    )
    arg_parse.add_argument(
        "--meta", metavar="", help="convert from a Metasploit Payload UUID"
    )
    arg_parse.add_argument(
        "--moto", metavar="", help="convert from Motorola's 6-byte value"
    )
    arg_parse.add_argument(
        "--ms1904", metavar="", help="convert from MS Excel 1904 Date format"
    )
    arg_parse.add_argument(
        "--msdos", metavar="", help="convert from 32-bit MS-DOS time, result is Local"
    )
    arg_parse.add_argument(
        "--nokia", metavar="", help="convert from a Nokia 4-byte value"
    )
    arg_parse.add_argument(
        "--nokiale", metavar="", help="convert from a Nokia 4-byte LE value"
    )
    arg_parse.add_argument(
        "--ns40", metavar="", help="convert from a Nokia S40 7-byte value"
    )
    arg_parse.add_argument(
        "--ns40le", metavar="", help="convert from a Nokia S40 7-byte LE value"
    )
    arg_parse.add_argument(
        "--nsdate",
        metavar="",
        help="convert from an Apple NSDate (iOS, BPList, Cocoa, Mac Absolute)",
    )
    arg_parse.add_argument(
        "--oleb",
        metavar="",
        help="convert from a Windows OLE 64-bit BE value, remove 0x & space\n"
        "- example from SRUM: 0x40e33f5d 0x97dfe8fb should be 40e33f5d97dfe8fb",
    )
    arg_parse.add_argument(
        "--olel", metavar="", help="convert from a Windows OLE 64-bit LE value"
    )
    arg_parse.add_argument("--pr", metavar="", help="convert from Mozilla's PRTime")
    arg_parse.add_argument(
        "--s32", metavar="", help="convert from an S32-encoded value"
    )
    arg_parse.add_argument(
        "--semi", metavar="", help="convert from a Semi-Octet decimal value"
    )
    arg_parse.add_argument(
        "--sony", metavar="", help="convert from a Sonyflake URL value"
    )
    arg_parse.add_argument(
        "--sym", metavar="", help="convert from Symantec's 6-byte AV value"
    )
    arg_parse.add_argument(
        "--systime", metavar="", help="convert from a 128-bit SYSTEMTIME value"
    )
    arg_parse.add_argument(
        "--tiktok", metavar="", help="convert from a TikTok URL value"
    )
    arg_parse.add_argument(
        "--twitter", metavar="", help="convert from a Twitter URL value"
    )
    arg_parse.add_argument("--uhbe", metavar="", help="convert from Unix Hex 32-bit BE")
    arg_parse.add_argument("--uhle", metavar="", help="convert from Unix Hex 32-bit LE")
    arg_parse.add_argument("--unix", metavar="", help="convert from Unix Seconds")
    arg_parse.add_argument("--umil", metavar="", help="convert from Unix Milliseconds")
    arg_parse.add_argument(
        "--umilhex", metavar="", help="convert from Unix Milliseconds 6-byte Hex value"
    )
    arg_parse.add_argument(
        "--uu",
        metavar="",
        help="convert from a UUID: 00000000-0000-0000-0000-000000000000",
    )
    arg_parse.add_argument(
        "--vm",
        metavar="",
        help="convert from a VMWare Snapshot (.vmsd) value\n"
        '- enter as "high value,low value"',
    )
    arg_parse.add_argument(
        "--wh", metavar="", help="convert from Windows 64-bit Hex BE"
    )
    arg_parse.add_argument(
        "--whle", metavar="", help="convert from Windows 64-bit Hex LE"
    )
    arg_parse.add_argument(
        "--version", "-v", action="version", version=arg_parse.description
    )

    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()

    args = arg_parse.parse_args()
    analyze(args)


if __name__ == "__main__":
    main()
