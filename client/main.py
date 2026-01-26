import os
import sys
import mimetypes
import traceback
from datetime import datetime
import json

from shiboken6 import isValid
from PySide6.QtWidgets import QStyledItemDelegate, QApplication, QStyle, QStyleOptionButton
from PySide6.QtCore import QRect, QEvent
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PySide6.QtWidgets import QComboBox
from umbral import SecretKey,pre,keys,Signer
import base64
from PySide6.QtWidgets import QScrollArea, QGridLayout, QDialog, QTextEdit, QDialogButtonBox
from PySide6.QtCore import (
    Qt, QByteArray, QSortFilterProxyModel, QObject, Signal, QRunnable, QThreadPool
)
from PySide6.QtGui import QIcon, QPixmap, QStandardItem, QStandardItemModel
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QFrame, QMessageBox, QCheckBox,
    QFileDialog, QTableView, QHeaderView, QAbstractItemView,
    QInputDialog
)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path


BASE_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:5000").rstrip("/")


class WorkerSignals(QObject):
    ok = Signal(object)         
    err = Signal(str, object)  

class ApiJob(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def run(self):
        try:
            res = self.fn(*self.args, **self.kwargs)
            self.signals.ok.emit(res)
        except Exception as e:
            tb = traceback.format_exc()
            self.signals.err.emit(str(e), tb)

class ApiClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def post_json(self, path: str, payload: dict, timeout=12):
        r = self.session.post(self._url(path), json=payload, timeout=timeout)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data

    def get_json(self, path: str, params: dict | None = None, timeout=12):
        r = self.session.get(self._url(path), params=params or {}, timeout=timeout)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data

api = ApiClient(BASE_URL)
pool = QThreadPool.globalInstance()


def icon_from_svg(svg_text: str, size: int = 18) -> QIcon:
    renderer = QSvgRenderer(QByteArray(svg_text.encode("utf-8")))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    from PySide6.QtGui import QPainter
    p = QPainter(pixmap)
    renderer.render(p)
    p.end()
    return QIcon(pixmap)

SVG_USER = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#CFE7FF">
  <path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-4.4 0-8 2.2-8 5v1h16v-1c0-2.8-3.6-5-8-5Z"/>
</svg>
"""
SVG_KEY = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#CFE7FF">
  <path d="M7 14a5 5 0 1 1 4.9-6H22v4h-2v2h-2v2h-4.1A5 5 0 0 1 7 14Zm0-3a2 2 0 1 0-2-2 2 2 0 0 0 2 2Z"/>
</svg>
"""
SVG_SPARK = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#0B1220">
  <path d="M12 2l1.6 6.2L20 10l-6.4 1.8L12 18l-1.6-6.2L4 10l6.4-1.8L12 2Z"/>
</svg>
"""
SVG_UPLOAD = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#EAF2FF">
  <path d="M5 20h14v-2H5v2Zm7-18-5.5 5.5 1.42 1.42L11 6.84V16h2V6.84l3.08 3.08 1.42-1.42L12 2Z"/>
</svg>
"""
SVG_REFRESH = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#BFD4FF">
  <path d="M17.65 6.35A7.95 7.95 0 0 0 12 4V1L7 6l5 5V7a6 6 0 1 1-6 6H4a8 8 0 1 0 13.65-6.65Z"/>
</svg>
"""
SVG_SEARCH = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#BFD4FF">
  <path d="M10 2a8 8 0 1 0 5.29 14l4.7 4.7 1.41-1.41-4.7-4.7A8 8 0 0 0 10 2Zm0 2a6 6 0 1 1-6 6 6 6 0 0 1 6-6Z"/>
</svg>
"""
SVG_FILE = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#CFE7FF">
  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Zm0 2 6 6h-6Z"/>
</svg>
"""
SVG_FOLDER = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#CFE7FF">
  <path d="M10 4 12 6h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h6Z"/>
</svg>
"""

SVG_LOGOUT = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#CFE7FF">
  <path d="M10 17v-2h4v-6h-4V7l-5 5 5 5Z"/>
  <path d="M19 3H11a2 2 0 0 0-2 2v2h2V5h8v14h-8v-2H9v2a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2Z"/>
</svg>
"""
SVG_LOCK = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#EAF2FF">
  <path d="M12 1a5 5 0 0 0-5 5v4H5v13h14V10h-2V6a5 5 0 0 0-5-5Zm-3 9V6a3 3 0 1 1 6 0v4H9Z"/>
</svg>
"""
def human_size(num_bytes: int) -> str:
    if num_bytes < 0:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(num_bytes)
    for u in units:
        if n < 1024.0 or u == units[-1]:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024.0
    return f"{num_bytes} B"

def file_type_label(path: str) -> str:
    if os.path.isdir(path):
        return "Folder"
    mt, _ = mimetypes.guess_type(path)
    if mt is None:
        return "File"
    if mt.startswith("image/"):
        return "Image"
    if mt.startswith("video/"):
        return "Video"
    if mt.startswith("audio/"):
        return "Audio"
    if mt in ("application/pdf",):
        return "PDF"
    if mt.startswith("text/"):
        return "Text"
    return mt.split("/")[1].upper() if "/" in mt else "File"


class AppState:
    def __init__(self):
        self.username = ""
        self.role = ""
        self.ecc_public_key = ""

        self.user_id = None

    def clear(self):
        self.username = ""
        self.role = ""
        self.ecc_public_key = ""
        self.user_id = None


STATE = AppState()


class DriveWindow(QWidget):
    COL_NAME = 0
    COL_OWNER = 1
    COL_MODIFIED = 2
    COL_ACTION = 3
    HEADERS = ["Name", "Owner", "Uploaded", "Action"]

    ROLE_ATTACHMENT_ID = Qt.UserRole + 10
    ROLE_OWNER_ID = Qt.UserRole + 11

    def __init__(self, on_logout):
        super().__init__()
        self.on_logout = on_logout
        self.setWindowTitle(f"Proiect • {STATE.username}")
        self.setFixedSize(1150, 700)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint |
            Qt.MSWindowsFixedSizeDialogHint
        )
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, False)
        self._apply_styles()
        self._build_ui()

        self.refresh_attachments()

    def _maybe_ask_user_id(self):
        if STATE.user_id is not None:
            return
        val, ok = QInputDialog.getInt(
            self,
            "User ID (optional)",
            "Backend-ul nu trimite user_id la login.\nDacă vrei să trimiți cereri de acces, introdu ID-ul tău numeric.\n(Altminteri, lasă 0.)",
            0, 0, 10**9, 1
        )
        if ok and val > 0:
            STATE.user_id = int(val)

    def _apply_styles(self):
        self.setStyleSheet("""
            QWidget { background: #070A12; color: #EAF2FF; font-family: Inter, Segoe UI, Arial; }

            #Shell {
                border-radius: 26px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0A1023, stop:0.35 #090A12, stop:0.70 #0A0F1E, stop:1 #070A12);
                border: 1px solid rgba(255,255,255,0.06);
            }

            #Sidebar {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.10);
                border-radius: 22px;
            }

            QLabel#Brand { font-size: 18px; font-weight: 900; }
            QLabel#Muted { color: rgba(234,242,255,0.65); font-size: 12px; }

            QPushButton#SideBtn {
                text-align: left;
                padding: 10px 12px;
                border-radius: 14px;
                background: rgba(255,255,255,0.03);
                border: 1px solid rgba(255,255,255,0.10);
                color: rgba(234,242,255,0.92);
            }
            QPushButton#SideBtn:hover { border: 1px solid rgba(34,211,238,0.65); }
            QPushButton#SideBtn:pressed { background: rgba(34,211,238,0.10); }

            QLineEdit {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.14);
                border-radius: 14px;
                padding: 10px 12px;
                color: #EAF2FF;
                font-size: 13px;
            }
            QLineEdit:focus { border: 1px solid rgba(34,211,238,0.85); }

            QPushButton#UploadBtn {
                background: rgba(34,211,238,0.18);
                border: 1px solid rgba(34,211,238,0.55);
                border-radius: 14px;
                padding: 10px 14px;
                font-weight: 900;
                color: #EAF2FF;
                font-size: 13px;
            }
            QPushButton#UploadBtn:hover {
                background: rgba(34,211,238,0.24);
                border: 1px solid rgba(34,211,238,0.85);
            }

            QPushButton#GhostBtn {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 14px;
                padding: 10px 14px;
                font-weight: 700;
                color: rgba(234,242,255,0.92);
                font-size: 13px;
            }
            QPushButton#GhostBtn:hover {
                border: 1px solid rgba(167,139,250,0.75);
                background: rgba(167,139,250,0.10);
            }

            QTableView {
                background: rgba(255,255,255,0.03);
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 16px;
                gridline-color: rgba(255,255,255,0.06);
                selection-background-color: rgba(34,211,238,0.16);
                selection-color: #EAF2FF;
                font-size: 13px;
            }
            QHeaderView::section {
                background: rgba(255,255,255,0.04);
                border: none;
                border-bottom: 1px solid rgba(255,255,255,0.10);
                padding: 10px 10px;
                color: rgba(234,242,255,0.80);
                font-weight: 700;
            }
        """)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)

        shell = QFrame()
        shell.setObjectName("Shell")
        shell_l = QHBoxLayout(shell)
        shell_l.setContentsMargins(18, 18, 18, 18)
        shell_l.setSpacing(14)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(270)
        s = QVBoxLayout(sidebar)
        s.setContentsMargins(16, 16, 16, 16)
        s.setSpacing(12)

      #  brand = QLabel("Proiect")
       # brand.setObjectName("Brand")

        # info = QLabel(
        #     f"<span style='color:rgba(234,242,255,0.65);font-size:12px;'>Signed in as</span><br>"
        #     f"<b>{STATE.username}</b><br>"
        #     f"<span style='color:rgba(234,242,255,0.65);font-size:12px;'>Backend:</span><br>"
        #     f"<span style='color:rgba(234,242,255,0.82);font-size:12px;'>{BASE_URL}</span>"
        # )

        btn_my = QPushButton("  My Drive")
        btn_my.setObjectName("SideBtn")
        btn_my.setIcon(icon_from_svg(SVG_FOLDER, 18))



        btn_requests = QPushButton("  Requests")
        btn_requests.setObjectName("SideBtn")
        btn_requests.setIcon(icon_from_svg(SVG_SPARK, 18))
        btn_requests.clicked.connect(self.open_requests)

        btn_logout = QPushButton("  Logout")
        btn_logout.setObjectName("SideBtn")
        btn_logout.setIcon(icon_from_svg(SVG_LOGOUT, 18))  
        btn_logout.clicked.connect(self.logout)

        
        #s.addWidget(brand)
        #s.addWidget(info)
        s.addSpacing(8)
        s.addWidget(btn_my)
        s.addWidget(btn_requests)
        s.addStretch(1)
        s.addWidget(btn_logout)
        main = QFrame()
        main.setStyleSheet("background: transparent;")
        m = QVBoxLayout(main)
        m.setContentsMargins(6, 6, 6, 6)
        m.setSpacing(12)

        top = QHBoxLayout()
        top.setSpacing(10)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search attachments…")
        self.search.addAction(icon_from_svg(SVG_SEARCH, 18), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self._apply_filter)

        upload_btn = QPushButton("Upload file")
        upload_btn.setObjectName("UploadBtn")
        upload_btn.setIcon(icon_from_svg(SVG_UPLOAD, 18))
        upload_btn.clicked.connect(self.add_attachments_metadata)


        top.addWidget(self.search, 1)
        top.addWidget(upload_btn, 0)

        self.model = QStandardItemModel(0, len(self.HEADERS))
        self.model.setHorizontalHeaderLabels(self.HEADERS)

        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)

        self.table = QTableView()
        self.table.setMouseTracking(True)
        self.table.viewport().setMouseTracking(True)
        self.table.setModel(self.proxy)
        self.table.setItemDelegateForColumn(self.COL_ACTION, RequestButtonDelegate(self.table, self))
        self.table.setSortingEnabled(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_NAME, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_OWNER, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_MODIFIED, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(self.COL_ACTION, QHeaderView.ResizeToContents)

        self.table.doubleClicked.connect(self.open_selected_info)



        m.addLayout(top)
        m.addWidget(self.table, 1)

        shell_l.addWidget(sidebar)
        shell_l.addWidget(main, 1)
        root.addWidget(shell)


    def open_requests(self):
        self.hide()
        self.req_win = RequestsWindow(
            on_logout=self.on_logout,         
            on_back_to_drive=self._back_from_requests
        )
        self.req_win.show()

    def _back_from_requests(self):
        self.show()
    def logout(self):
        # confirmare (optional)
        ans = QMessageBox.question(
            self,
            "Logout",
            "Sigur vrei să te deloghezi?",
            QMessageBox.Yes | QMessageBox.No
        )
        if ans != QMessageBox.Yes:
            return

        STATE.clear()
        api.session.cookies.clear()

        self.close()
        self.on_logout()

    def _apply_filter(self, text: str):
        self.proxy.setFilterFixedString(text)

    def _clear_rows(self):
        self.model.removeRows(0, self.model.rowCount())

    def _add_row(self, attachment_id: int, name: str, owner: str, modified_str: str, owner_id: int):
        icon = icon_from_svg(SVG_FILE, 18)
        name_item = QStandardItem(icon, f"  {name}")
        name_item.setData(name, Qt.UserRole)
        name_item.setData(int(attachment_id), self.ROLE_ATTACHMENT_ID)

        owner_item = QStandardItem(owner)
        mod_item = QStandardItem(modified_str)

        action_item = QStandardItem("Request")  
        action_item.setData(int(attachment_id), self.ROLE_ATTACHMENT_ID)
        action_item.setData(int(owner_id), self.ROLE_OWNER_ID)
        self.model.appendRow([name_item, owner_item, mod_item, action_item])

    def refresh_attachments(self):
        def job():
            return api.get_json("/v1/api/attachment/get")

        j = ApiJob(job)
        j.signals.ok.connect(self._on_attachments_loaded)
        j.signals.err.connect(self._on_api_error)
        pool.start(j)

    def _on_attachments_loaded(self, res):
        status_code, data = res
        print(data)
        if status_code != 200:
            #self.status.setText(f"Failed to load: {data}")
            QMessageBox.warning(self, "Backend error", str(data))
            return

        self._clear_rows()
        # owner_id = 0
        # fname = ""
        # up = ""
        # owner_id = ""
        # owner_name = ""
        for a in (data or []):
            aid = a.get("id", 0)
            fname = a.get("filename", "")
            up = a.get("uploaded_at", "")
            owner_id = a.get("owned_by", "")
            owner_name = str(owner_id)
            if owner_id:
                sc, user_data = api.get_json("/v1/api/auth/getUserById", params={"user_id": owner_id})
                if sc == 200 and user_data:
                    owner_name = user_data.get("username", str(owner_id))

            self._add_row(
                attachment_id=aid,
                name=fname,
                owner=owner_name,
                modified_str=str(up),
                owner_id=int(owner_id)
            )

    def post_multipart(self, path: str, data: dict, files: dict, timeout=60):
            r = self.session.post(self._url(path), data=data, files=files, timeout=timeout)
            try:
                resp = r.json()
            except Exception:
                resp = {"raw": r.text}
            return r.status_code, resp
    

    def add_attachments_metadata(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select file(s) to upload (encrypted)")
        if not paths:
            return

        def aes_encrypt_bytes(plain: bytes):
            key = os.urandom(32)      
            iv = os.urandom(12)       
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, plain, None)
            return ciphertext, key, iv
        
        def load_umbral_public_key(username: str):
            pk_path = Path("drive_keys") / f"{username}_umbral_public.key"
            pk_b64 = pk_path.read_text()
            return keys.PublicKey.from_bytes(
        base64.b64decode(pk_b64)
    )
      
        def encrypt_aes_key_umbral(aes_key: bytes, pubkey):
            capsule, ciphertext = pre.encrypt(pubkey, aes_key)

            capsule_bytes = bytes(capsule)

            encrypted_key_b64 = base64.b64encode(ciphertext).decode()
            capsule_b64 = base64.b64encode(capsule_bytes).decode()
            
            return encrypted_key_b64, capsule_b64



        def job():
            ok = 0
            errors = []

            for p in paths:
                name = os.path.basename(p)

                try:
                    plain = Path(p).read_bytes()

                    encrypted_content, aes_key, iv = aes_encrypt_bytes(plain)


                    owner_pubkey = load_umbral_public_key(STATE.username)

                    encrypted_key_b64, capsule_b64 = encrypt_aes_key_umbral(
                        aes_key,
                        owner_pubkey
                    )
                    
                    iv_b64 = base64.b64encode(iv).decode()

                    payload = {
                        "filename": name,
                        "owner_id": str(STATE.user_id),
                        "encrypted_aes_key": encrypted_key_b64,
                        "capsule": capsule_b64,
                        "iv": iv_b64
                    }


        

                    sc, data= api.get_json(f"/v1/api/attachment/presignedUrl", params={"object_name": name})
                
                    presigned_url = data["url"]

                    requests.put(
                        presigned_url,
                        data=encrypted_content,
                        headers={"Content-Type": "application/octet-stream"}
                    )

                    sc, data = api.post_json("/v1/api/attachment/add", payload)
                    if sc != 200:
                        errors.append((name, sc, data))
                        continue

                    ok += 1

                except Exception as e:
                    print(str(e))
                    errors.append((name, 0, str(e)))

            return ok, errors

        j = ApiJob(job)
        j.signals.ok.connect(self._on_added_metadata)
        j.signals.err.connect(self._on_api_error)
        pool.start(j)

    def _on_added_metadata(self, res):
        ok, errors = res
        if errors:
            msg = "\n".join([f"- {n}: {sc} {d}" for (n, sc, d) in errors[:8]])
            if len(errors) > 8:
                msg += f"\n… (+{len(errors)-8} more)"
            QMessageBox.warning(self, "Some adds failed", msg)

        self.refresh_attachments()

    def _selected_attachment_id(self):
        idx = self.table.selectionModel().currentIndex()
        if not idx.isValid():
            return None
        src = self.proxy.mapToSource(idx)
        row = src.row()
        item = self.model.item(row, self.COL_NAME)
        if not item:
            return None
        return item.data(self.ROLE_ATTACHMENT_ID)


    def _on_request_created(self, res):
        sc, data = res
        if sc == 200:
            QMessageBox.information(self, "Request created", str(data))
            self.status.setText("Request created.")
        else:
            QMessageBox.warning(self, "Request failed", str(data))
            self.status.setText("Request failed.")

    def open_selected_info(self):
        idx = self.table.selectionModel().currentIndex()
        if not idx.isValid():
            return
        src = self.proxy.mapToSource(idx)
        row = src.row()
        name_item = self.model.item(row, self.COL_NAME)
        name = name_item.data(Qt.UserRole)
        aid = name_item.data(self.ROLE_ATTACHMENT_ID)
        owner = self.model.item(row, self.COL_OWNER).text()
        mod = self.model.item(row, self.COL_MODIFIED).text()

        QMessageBox.information(
            self, "Attachment details",
            f"ID: {aid}\nName: {name}\nOwner: {owner}\n or '-'\nUploaded: {mod}\n\n"
            f"Backend: {BASE_URL}"
        )

    def _on_api_error(self, msg, tb):
        QMessageBox.critical(self, "API error", f"{msg}\n\n{tb}")
        self.status.setText("Error.")


    def create_request_for_attachment(self, attachment_id: int, owner_id: int):
        if STATE.user_id is None:
            self._maybe_ask_user_id()
            if STATE.user_id is None:
                return

        try:
            current_id = int(STATE.user_id)
            owner_id = int(owner_id)
        except Exception:
            current_id = 0
            owner_id = 0
        if owner_id and current_id and owner_id == current_id:
            box = QMessageBox(self)
            box.setWindowTitle("Nu se poate")
            box.setIcon(QMessageBox.Warning)
            box.setText("Nu poți crea request pentru propriul fișier.")
            box.setStyleSheet("QLabel{min-width:520px; min-height:120px;}")
            box.exec()
            return

        ans = QMessageBox.question(
            self,
            "Create request",
            f"Create request for attachment #{attachment_id}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if ans != QMessageBox.Yes:
            return

        def job():
            return api.post_json("/v1/api/request/create", {
                "resource_id": int(attachment_id),
                "requested_by": int(STATE.user_id)
            })

        j = ApiJob(job)

        if not hasattr(self, "_jobs"):
            self._jobs = []
        self._jobs.append(j)

        def cleanup():
            try:
                self._jobs.remove(j)
            except ValueError:
                pass

        def _ok(res):
            cleanup()
            sc, data = res

            if isinstance(data, dict):
                msg = data.get("message") or data.get("error") or "OK"
            else:
                msg = str(data)

            box = QMessageBox(self)
            box.setWindowTitle("Request created" if sc == 200 else "Request failed")
            box.setIcon(QMessageBox.Information if sc == 200 else QMessageBox.Warning)
            box.setText(msg)
            box.setStyleSheet("QLabel{min-width:520px; min-height:120px;}")
            box.exec()

        def _err(msg, tb):
            cleanup()
            box = QMessageBox(self)
            box.setWindowTitle("API error")
            box.setIcon(QMessageBox.Critical)
            box.setText(str(msg))
            box.setStyleSheet("QLabel{min-width:520px; min-height:120px;}")
            box.exec()

        j.signals.ok.connect(_ok)
        j.signals.err.connect(_err)
        pool.start(j)



class RequestButtonDelegate(QStyledItemDelegate):
    def __init__(self, parent, drive_window):
        super().__init__(parent)
        self.drive = drive_window

    def paint(self, painter, option, index):
        opt = QStyleOptionButton()
        opt.rect = option.rect.adjusted(6, 4, -6, -4)
        opt.text = "Request"
        opt.state = QStyle.State_Enabled

        if option.state & QStyle.State_MouseOver:
            opt.state |= QStyle.State_MouseOver

        QApplication.style().drawControl(QStyle.CE_PushButton, opt, painter)

    def editorEvent(self, event, model, option, index):
        if event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
            # index e din proxy; ia attachment_id din celula action (unde l-am setat)
            attachment_id = index.data(self.drive.ROLE_ATTACHMENT_ID)
            owner_id = index.data(self.drive.ROLE_OWNER_ID)

            if attachment_id:
                self.drive.create_request_for_attachment(int(attachment_id), int(owner_id or 0))
            return True
        return False


class RequestsWindow(QWidget):
    def __init__(self, on_logout, on_back_to_drive):
        super().__init__()
        self.on_logout = on_logout
        self.on_back_to_drive = on_back_to_drive
        self._jobs = []
#        self._cards = []
        self._requests = [] 
        self.setWindowTitle(f"Proiect • Requests • {STATE.username}")
        self.setFixedSize(1150, 700)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowCloseButtonHint |
            Qt.MSWindowsFixedSizeDialogHint
        )
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, False)

        self._apply_styles()
        self._build_ui()
        self.load_requests()
       # self._seed_demo()

    def _apply_styles(self):
        # Copiat ca vibe din DriveWindow + butoane / inputs
        self.setStyleSheet("""
            QWidget { background: #070A12; color: #EAF2FF; font-family: Inter, Segoe UI, Arial; }

            #Shell {
                border-radius: 26px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0A1023, stop:0.35 #090A12, stop:0.70 #0A0F1E, stop:1 #070A12);
                border: 1px solid rgba(255,255,255,0.06);
            }

            #Sidebar {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.10);
                border-radius: 22px;
            }

            QLabel#Brand { font-size: 18px; font-weight: 900; }
            QLabel#Muted { color: rgba(234,242,255,0.65); font-size: 12px; }

            QPushButton#SideBtn {
                text-align: left;
                padding: 10px 12px;
                border-radius: 14px;
                background: rgba(255,255,255,0.03);
                border: 1px solid rgba(255,255,255,0.10);
                color: rgba(234,242,255,0.92);
                font-weight: 700;
            }
            QPushButton#SideBtn:hover { border: 1px solid rgba(34,211,238,0.65); }
            QPushButton#SideBtn:pressed { background: rgba(34,211,238,0.10); }

            /* optional: “active” state for current page */
            QPushButton#SideBtnActive {
                text-align: left;
                padding: 10px 12px;
                border-radius: 14px;
                background: rgba(34,211,238,0.12);
                border: 1px solid rgba(34,211,238,0.55);
                color: rgba(234,242,255,0.98);
                font-weight: 800;
            }

            QLineEdit {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.14);
                border-radius: 14px;
                padding: 10px 12px;
                color: #EAF2FF;
                font-size: 13px;
            }
            QLineEdit:focus { border: 1px solid rgba(34,211,238,0.85); }

            QPushButton#UploadBtn {
                background: rgba(34,211,238,0.18);
                border: 1px solid rgba(34,211,238,0.55);
                border-radius: 14px;
                padding: 10px 14px;
                font-weight: 900;
                color: #EAF2FF;
                font-size: 13px;
            }
            QPushButton#UploadBtn:hover {
                background: rgba(34,211,238,0.24);
                border: 1px solid rgba(34,211,238,0.85);
            }

            QScrollArea { border: none; background: transparent; }
        """)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)

        shell = QFrame()
        shell.setObjectName("Shell")
        shell_l = QHBoxLayout(shell)
        shell_l.setContentsMargins(18, 18, 18, 18)
        shell_l.setSpacing(14)

        # ----- Sidebar (same structure as DriveWindow) -----
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(270)
        s = QVBoxLayout(sidebar)
        s.setContentsMargins(16, 16, 16, 16)
        s.setSpacing(12)

        btn_drive = QPushButton("  My Drive")
        btn_drive.setObjectName("SideBtn")
        btn_drive.setIcon(icon_from_svg(SVG_FOLDER, 18))
        btn_drive.clicked.connect(self.back_to_drive)

        btn_requests = QPushButton("  Requests")
        btn_requests.setObjectName("SideBtnActive")  # highlight current
        btn_requests.setIcon(icon_from_svg(SVG_SPARK, 18))
        btn_requests.setEnabled(True)

        btn_logout = QPushButton("  Logout")
        btn_logout.setObjectName("SideBtn")
        btn_logout.setIcon(icon_from_svg(SVG_LOGOUT, 18))
        btn_logout.clicked.connect(self.logout)

        s.addWidget(btn_drive)
        s.addWidget(btn_requests)
        s.addStretch(1)
        s.addWidget(btn_logout)

        # ----- Main -----
        main = QFrame()
        main.setStyleSheet("background: transparent;")
        m = QVBoxLayout(main)
        m.setContentsMargins(6, 6, 6, 6)
        m.setSpacing(12)

        # ----- Top bar (ONLY ONE) -----
        top = QHBoxLayout()
        top.setSpacing(10)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search requests…")
        self.search.textChanged.connect(self._rebuild_grid)

        self.status_combo = QComboBox()
        self.status_combo.setStyleSheet("""
            QComboBox {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.14);
                border-radius: 14px;
                padding: 8px 10px;
                color: #EAF2FF;
                font-size: 13px;
            }
            QComboBox:focus { border: 1px solid rgba(34,211,238,0.85); }
            QComboBox QAbstractItemView {
                background: #0A1023;
                border: 1px solid rgba(255,255,255,0.12);
                selection-background-color: rgba(34,211,238,0.20);
                color: #EAF2FF;
            }
        """)
        self.status_combo.addItems(["Pending", "Approved", "Rejected"])
        self.status_combo.currentTextChanged.connect(lambda _: self.load_requests())



        top.addWidget(self.search, 1)
        top.addWidget(self.status_combo, 0)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.grid_host = QWidget()
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(12)
        self.scroll.setWidget(self.grid_host)

        self.status = QLabel("Ready.")
        self.status.setStyleSheet("color: rgba(234,242,255,0.65); font-size: 12px; padding-left: 2px;")

        m.addLayout(top)
        m.addWidget(self.scroll, 1)
        m.addWidget(self.status)

        shell_l.addWidget(sidebar)
        shell_l.addWidget(main, 1)

        root.addWidget(shell)

    def _on_api_error(self, msg, tb):
        QMessageBox.critical(self, "API error", f"{msg}\n\n{tb}")
        if hasattr(self, "status") and self.status is not None:
            self.status.setText("Error.")

    def load_requests(self):
        status = self.status_combo.currentText().strip().lower()
        self.status.setText("Loading requests…")

        def job():
            return api.get_json("/v1/api/request/get", params={"status": status, "user_id": STATE.user_id})

        j = ApiJob(job)
        j.signals.ok.connect(self._on_requests_loaded)
        j.signals.err.connect(self._on_api_error)
        pool.start(j)

    def _on_requests_loaded(self, res):
        sc, data = res
        if sc != 200:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("AABackend error")
            msg.setText(str(data))

            msg.setStyleSheet("""
            QLabel {
                min-width: 500px;
            }
            """)

            msg.exec()

            self.status.setText("Failed to load.")
            return

        self._requests = data if isinstance(data, list) else []
        self._rebuild_grid()
        self.status.setText(f"Loaded {len(self._requests)} request(s).")

    # def _seed_demo(self):
    #     for i in range(1, 16):
    #         self._cards.append({
    #             "title": f"Request #{i}",
    #             "message": "Vreau acces la fișierul X / permisiune Y. (demo frontend)",
    #             "meta": f"{datetime.now().strftime('%Y-%m-%d %H:%M')} • status: Pending"
    #         })
    #     self._rebuild_grid()

    def _rebuild_grid(self, *_):
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)

        q = self.search.text().strip().lower()

        visible = []
        for r in self._requests:
            rid = r.get("id", "")
            resource_id = r.get("resource_id", "")
            requested_by = r.get("requested_by", "")
            status = r.get("request_status", "")
            created_at = r.get("created_at", "")

            blob = f"{rid} {resource_id} {requested_by} {status} {created_at}".lower()
            if not q or q in blob:
                visible.append(r)

        for idx, r in enumerate(visible):
            row = idx // 3
            col = idx % 3
            card = RequestCard(
                rid=r.get("id", 0),
                resource_id=r.get("resource_id", 0),
                requested_by=r.get("requested_by", 0),
                status=r.get("request_status", ""),
                created_at=str(r.get("created_at", "")),
                on_decision=self._change_request_status,
                on_download=self._download_attachment,
            )
            self.grid.addWidget(card, row, col)

        self.grid.setColumnStretch(0, 1)
        self.grid.setColumnStretch(1, 1)
        self.grid.setColumnStretch(2, 1)

        self.status.setText(f"{len(visible)} request(s) shown")

    def _change_request_status(self, request_id: int, new_status: str, requested_by: int):
        self.status.setText(f"Updating request #{request_id} → {new_status}…")
        print("requested_by =", requested_by)
        print("new status: ", new_status)


        def job():
            return api.post_json("/v1/api/request/changeStatus", {
                "id": int(request_id),
                "new_status": new_status
            })

        j = ApiJob(job)

        self._jobs.append(j)
        
        def cleanup():
            try:
                self._jobs.remove(j)
            except ValueError:
                pass
        
        def _ok(res):
            cleanup()
            sc, data = res
            if sc != 200:
                QMessageBox.warning(self, "Update failed", str(data))
                self.status.setText("Update failed.")
                return
            self.load_requests()

            if new_status == "approved":
                self._fetch_requester_public_key(requested_by)

        def _err(msg, tb):
            cleanup()
            self._on_api_error(msg, tb)

        j.signals.ok.connect(_ok)
        j.signals.err.connect(_err)
        pool.start(j)

    def _fetch_requester_public_key(self, requested_by: int):
        def job():
            return api.get_json(
                "/v1/api/auth/getKey",
                params={"user_id": int(requested_by)}
            )

        j = ApiJob(job)
        self._jobs.append(j)

        def cleanup():
            try:
                self._jobs.remove(j)
            except ValueError:
                pass

        def _ok(res):
            cleanup()
            sc, data = res
            if sc != 200:
                QMessageBox.warning(self, "Key error", str(data))
                return

            print("SUNT AICI")

            ecc_public_key = data.get("ecc_public_key")
            if not ecc_public_key:
                QMessageBox.warning(self, "Key error", "Missing receiver ecc_public_key")
                return

           
            enc_sk_path = Path("drive_keys") / f"{STATE.username}_umbral_private.key"
            enc_sk_b64 = enc_sk_path.read_text().strip()
            delegating_sk = SecretKey.from_bytes(base64.b64decode(enc_sk_b64))

          
            sign_sk_path = Path("drive_keys") / f"{STATE.username}_signing_private.key"
            sign_sk_b64 = sign_sk_path.read_text().strip()

            signing_sk = SecretKey.from_bytes(base64.b64decode(sign_sk_b64))
            signer = Signer(signing_sk)

            receiving_pk = keys.PublicKey.from_bytes(base64.b64decode(ecc_public_key))

            print("LOCAL VERIFY KEY:", base64.b64encode(bytes(signer.verifying_key())).decode())

            kfrags = pre.generate_kfrags(
                delegating_sk=delegating_sk,
                receiving_pk=receiving_pk,
                signer=signer,      
                shares=1,
                threshold=1
            )



            prekey_value = base64.b64encode(bytes(kfrags[0])).decode()

            self._send_prekey(
                requested_by=requested_by,
                prekey_value=prekey_value
            )

        def _err(msg, tb):
            cleanup()
            self._on_api_error(msg, tb)

        j.signals.ok.connect(_ok)
        j.signals.err.connect(_err)

        pool.start(j)  
    def _send_prekey(self, requested_by: int, prekey_value: str):
        def job():
            return api.post_json("/v1/api/keys/add", {
                "secret_key_user_id": STATE.user_id,
                "public_key_user_id": requested_by,
                "prekey_value": prekey_value
            })

        j = ApiJob(job)
        self._jobs.append(j)

        def cleanup():
            try:
                self._jobs.remove(j)
            except ValueError:
                pass

        def _ok(res):
            cleanup()
            sc, data = res
            if sc != 200:
                QMessageBox.warning(self, "Prekey error", str(data))
                return
            print("✅ Prekey salvat cu succes")
            self.status.setText("Access approved & key shared.")

        def _err(msg, tb):
            cleanup()
            self._on_api_error(msg, tb)

        j.signals.ok.connect(_ok)
        j.signals.err.connect(_err)
        pool.start(j)

    #TODO: download
    def _download_attachment(self, attachment_id: int, btn: QPushButton):
        if hasattr(self, "status") and self.status is not None:
            self.status.setText(f"Downloading & decrypting attachment #{attachment_id}…")

        def job():
          
            sc1, meta = api.get_json(
                "/v1/api/attachment/getById",
                params={"id": int(attachment_id)}
            )
            if sc1 != 200:
                return ("err", sc1, meta)

            filename = meta.get("filename")
            if not filename:
                return ("err", 0, {"error": "No filename returned"})

            r = api.session.get(
                api._url("/v1/api/attachment/getModel"),
                params={"source_model": filename, "user_id": STATE.user_id},
                timeout=60
            )
            if r.status_code != 200:

                try:
                    return ("err", r.status_code, r.json())
                except Exception:
                    return ("err", r.status_code, {"raw": r.text})

            encrypted_file_bytes = r.content

            sc3, crypto = api.get_json(
                "/v1/api/attachment/getAESKey",
                params={"filename": filename, "user_id": STATE.user_id}
            )
            if sc3 != 200:
                return ("err", sc3, crypto)

            owner_id = crypto.get("owner_id")
            if not owner_id:
                return ("err", 0, {"error": "owner_id missing"})

            sc4, owner_key = api.get_json(
                "/v1/api/auth/getKey",
                params={"user_id": int(owner_id)}
            )
            if sc4 != 200:
                return ("err", sc4, owner_key)
            print("AICI 1")
            a_pk_b64 = owner_key.get("ecc_public_key")
            if not a_pk_b64:
                return ("err", 0, {"error": "owner ecc_public_key missing"})
            print("AICI 2")
            owner_signing_pk_b64 = owner_key.get("signing_public_key")
            if not owner_signing_pk_b64:
                return ("err", 0, {"error": "Owner signing_public_key missing from /auth/getKey"})

            # 5) load receiver private key (Bob)
            b_sk_path = Path("drive_keys") / f"{STATE.username}_umbral_private.key"
            b_sk_b64 = b_sk_path.read_text().strip()
            b_sk = keys.SecretKey.from_bytes(base64.b64decode(b_sk_b64))

            # 6) build owner public keys objects
            a_pk = keys.PublicKey.from_bytes(base64.b64decode(a_pk_b64))
            owner_verifying_pk = keys.PublicKey.from_bytes(base64.b64decode(owner_signing_pk_b64))

            # 7) encrypted AES key (Umbral ciphertext)
            try:
                encrypted_aes_key = base64.b64decode(crypto["encrypted_aes_key"])
            except Exception:
                return ("err", 0, {"error": "Invalid encrypted_aes_key base64"})
            print("AICI 6")  
            # 8) capsule
            try:
                capsule = pre.Capsule.from_bytes(base64.b64decode(crypto["capsule"]))
            except Exception as e:
                return ("err", 0, {"error": "Invalid capsule", "details": str(e)})
            print("AICI 7")  
            # 9) cfrags
            cfrags_b64 = crypto.get("cfrags") or []
            if not cfrags_b64:
                return ("err", 0, {"error": "No cfrags received"})
            print("AICI 8")  
            try:
                cfrags = [pre.CapsuleFrag.from_bytes(base64.b64decode(x)) for x in cfrags_b64]
            except Exception as e:
                return ("err", 0, {"error": "Invalid cfrag bytes", "details": str(e)})
            print("AICI 9")  
            # 9.5) verify cfrags -> VerifiedCapsuleFrag
            receiving_pk = b_sk.public_key()
            print("AICI 10")  
            verified_cfrags = []
            for cf in cfrags:
                vcf = cf.verify(
                    capsule=capsule,
                    verifying_pk=owner_verifying_pk,
                    delegating_pk=a_pk,
                    receiving_pk=receiving_pk,
                )
                verified_cfrags.append(vcf)
            print("AICI 13") 
            # 10) decrypt re-encrypted AES key (IMPORTANT: positional args!)
            try:
                print("AICI 14")
                aes_key = pre.decrypt_reencrypted(
                    b_sk,
                    a_pk,
                    capsule,
                    verified_cfrags,
                    encrypted_aes_key
                )
            except Exception as e:
                print("AICI 15") 
                return ("err", 0, {"error": "decrypt_reencrypted failed", "details": str(e)})
            print("AICI 16")

            # 11) decrypt file (AES-GCM)
            try:
                iv = base64.b64decode(crypto["iv"])
                print("AICI 17")
            except Exception:
                print("AICI 171")
                return ("err", 0, {"error": "Invalid iv base64"})

            try:
                print("AICI 18")
                plain = AESGCM(aes_key).decrypt(iv, encrypted_file_bytes, None)
            except Exception as e:
                print("AICI 181")
                return ("err", 0, {"error": "AESGCM decrypt failed", "details": str(e)})
            print("AICI 19")    
            return ("ok", filename, plain)

        j = ApiJob(job)

        j.setAutoDelete(False)

        if not hasattr(self, "_jobs"):
            self._jobs = []
        self._jobs.append(j)

        def cleanup():
            try:
                self._jobs.remove(j)
            except ValueError:
                pass

        def safe_enable():
            if btn is not None and isValid(btn):
                btn.setEnabled(True)

        def _ok(res):
            cleanup()

            print("AICI !!!!")

            safe_enable() 
            if res[0] != "ok":
                print("PROBLEMAA !!!!")

                sc, data = res[1], res[2]
                # QMessageBox.warning(self, "Download failed", f"{sc}\n{data}")
                box = QMessageBox(self)
                box.setWindowTitle("Download failed")
                box.setIcon(QMessageBox.Warning)
                box.setText(f"{sc}\n{data}")

                # mărește fereastra
                box.setStyleSheet("""
                    QLabel {
                        min-width: 520px;
                        min-height: 140px;
                    }
                """)

                box.exec()
                if hasattr(self, "status") and self.status is not None:
                    self.status.setText("Download failed.")
                return

            _, filename, plain = res

            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save decrypted file", filename
            )
            if not save_path:
                if hasattr(self, "status") and self.status is not None:
                    self.status.setText("Save cancelled.")
                return

            Path(save_path).write_bytes(plain)

            QMessageBox.information(
                self, "Done", f"File decrypted & saved:\n{save_path}"
            )
            if hasattr(self, "status") and self.status is not None:
                self.status.setText("File decrypted successfully.")

        def _err(msg, tb):
            cleanup()

            safe_enable()
            QMessageBox.critical(self, "Decrypt error", f"{msg}\n\n{tb}")

        j.signals.ok.connect(_ok)
        j.signals.err.connect(_err)
        pool.start(j)

    def back_to_drive(self):
        self.close()
        self.on_back_to_drive()

    def logout(self):
        ans = QMessageBox.question(
            self, "Logout", "Sigur vrei să te deloghezi?",
            QMessageBox.Yes | QMessageBox.No
        )
        if ans != QMessageBox.Yes:
            return
        STATE.clear()
        api.session.cookies.clear()
        self.close()
        self.on_logout()

class RequestCard(QFrame):
    def __init__(self, rid: int, resource_id: int, requested_by: int, status: str, created_at: str, on_decision=None, on_download=None):
        super().__init__()
        self.setObjectName("ReqCard")
        self.setFixedHeight(170)
        self._resource_id = int(resource_id)
        self._rid = int(rid)
        self.btn_download = None
        self._status = (status or "").lower()
        self._on_decision = on_decision
        self._on_download = on_download
        self._requested_by = int(requested_by)
        st = (status or "").lower()
        if st in ("approved", "accept", "accepted"):
            badge_bg = "rgba(34,197,94,0.18)"    
            badge_bd = "rgba(34,197,94,0.55)"
        elif st in ("rejected", "deny", "denied"):
            badge_bg = "rgba(244,63,94,0.18)"     
            badge_bd = "rgba(244,63,94,0.55)"
        else:
            badge_bg = "rgba(251,191,36,0.16)"   
            badge_bd = "rgba(251,191,36,0.45)"

        self.setStyleSheet(f"""
            #ReqCard {{
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.10);
                border-radius: 18px;
            }}
            QLabel#ReqTitle {{ font-size: 14px; font-weight: 900; }}
            QLabel#ReqMeta  {{ font-size: 11px; color: rgba(234,242,255,0.55); }}
            QLabel#ReqLine  {{ font-size: 12px; color: rgba(234,242,255,0.82); }}
            QLabel#Badge {{
                background: {badge_bg};
                border: 1px solid {badge_bd};
                border-radius: 999px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 900;
                color: rgba(234,242,255,0.92);
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        title = QLabel(f"Request #{rid}")
        title.setObjectName("ReqTitle")

        badge = QLabel(status or "unknown")
        badge.setObjectName("Badge")

        top.addWidget(title, 1)
        top.addWidget(badge, 0, Qt.AlignRight)

        line1 = QLabel(f"Resource ID:  {resource_id}")
        line1.setObjectName("ReqLine")
        line2 = QLabel(f"Requested by: {requested_by}")
        line2.setObjectName("ReqLine")

        meta = QLabel(f"Created: {created_at}")
        meta.setObjectName("ReqMeta")

        layout.addLayout(top)
        layout.addWidget(line1)
        layout.addWidget(line2)
        layout.addStretch(1)
        layout.addWidget(meta)

        if self._status == "pending" and callable(self._on_decision):
            actions = QHBoxLayout()
            actions.setSpacing(10)

            btn_reject = QPushButton("Reject")
            btn_accept = QPushButton("Accept")

            btn_reject.setCursor(Qt.PointingHandCursor)
            btn_accept.setCursor(Qt.PointingHandCursor)

            btn_accept.setStyleSheet("""
                QPushButton {
                    background: rgba(34,197,94,0.18);
                    border: 1px solid rgba(34,197,94,0.55);
                    border-radius: 12px;
                    padding: 8px 12px;
                    font-weight: 900;
                    color: rgba(234,242,255,0.95);
                }
                QPushButton:hover {
                    border: 1px solid rgba(34,197,94,0.9);
                    background: rgba(34,197,94,0.26);
                }
            """)

            btn_reject.setStyleSheet("""
                QPushButton {
                    background: rgba(244,63,94,0.18);
                    border: 1px solid rgba(244,63,94,0.55);
                    border-radius: 12px;
                    padding: 8px 12px;
                    font-weight: 900;
                    color: rgba(234,242,255,0.95);
                }
                QPushButton:hover {
                    border: 1px solid rgba(244,63,94,0.9);
                    background: rgba(244,63,94,0.26);
                }
            """)

            def do_accept():
                ans = QMessageBox.question(self, "Approve request", f"Approve request #{self._rid}?",
                                           QMessageBox.Yes | QMessageBox.No)
                if ans == QMessageBox.Yes:
                    self._on_decision(self._rid, "approved", self._requested_by)

            def do_reject():
                ans = QMessageBox.question(self, "Reject request", f"Reject request #{self._rid}?",
                                           QMessageBox.Yes | QMessageBox.No)
                if ans == QMessageBox.Yes:
                    self._on_decision(self._rid, "rejected", self._requested_by)

            btn_accept.clicked.connect(do_accept)
            btn_reject.clicked.connect(do_reject)

            actions.addWidget(btn_reject, 1)
            actions.addWidget(btn_accept, 1)

            layout.addLayout(actions)
        
        if self._status == "approved" and callable(self._on_download):
            self.btn_download = QPushButton("Download")
            self.btn_download.setCursor(Qt.PointingHandCursor)

            self.btn_download.setStyleSheet("""
                QPushButton {
                    background: rgba(59,130,246,0.18);
                    border: 1px solid rgba(59,130,246,0.55);
                    border-radius: 12px;
                    padding: 8px 12px;
                    font-weight: 900;
                    color: rgba(234,242,255,0.95);
                }
                QPushButton:hover {
                    border: 1px solid rgba(59,130,246,0.9);
                    background: rgba(59,130,246,0.26);
                }
            """)

            self.btn_download.clicked.connect(self._on_download_clicked)            
            layout.addWidget(self.btn_download)

    def _on_download_clicked(self):
        if self.btn_download:
            self.btn_download.setEnabled(False)
        self._on_download(self._resource_id, self.btn_download)





class SignupGlass(QWidget):
    def __init__(self, on_back_to_login):
        super().__init__()
        self.on_back_to_login = on_back_to_login
        self._pending_jobs = []

        self.setWindowTitle("Proiect • Signup")
        self.setFixedSize(1040, 600)
        self.setStyleSheet(self._style())

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)

        shell = QFrame()
        shell.setObjectName("Shell")

        shell_l = QVBoxLayout(shell)
        shell_l.setContentsMargins(18, 18, 18, 18)
        shell_l.setSpacing(0)

        form = QFrame()
        form.setObjectName("Glass")  
        form.setFixedWidth(580)     
        form.setStyleSheet("background: rgba(255,255,255,0.06);")

        fl = QVBoxLayout(form)
        fl.setContentsMargins(26, 26, 26, 26)
        fl.setSpacing(14)

        title = QLabel("Creează cont")
        title.setStyleSheet("font-size: 26px; font-weight: 900;")


        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.addAction(icon_from_svg(SVG_USER, 18), QLineEdit.LeadingPosition)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Parolă (min 6 caractere)")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.addAction(icon_from_svg(SVG_KEY, 18), QLineEdit.LeadingPosition)

        self.password2 = QLineEdit()
        self.password2.setPlaceholderText("Confirmă parola")
        self.password2.setEchoMode(QLineEdit.Password)
        self.password2.addAction(icon_from_svg(SVG_KEY, 18), QLineEdit.LeadingPosition)

        self.btn_create = QPushButton("Creează cont")
        self.btn_create.setObjectName("GlowBtn")
        self.btn_create.clicked.connect(self.create_account)

        btn_back = QPushButton("Înapoi la login")
        btn_back.setObjectName("AltBtn")
        btn_back.clicked.connect(self.back)

        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(self.btn_create, 3)
        row.addWidget(btn_back, 2)

        self.footer = QLabel("Ready.")
        self.footer.setStyleSheet("font-size: 11px; color: rgba(234,242,255,0.55);")

        fl.addWidget(title)
        fl.addSpacing(10)
        fl.addWidget(self.username)
        fl.addWidget(self.password)
        fl.addWidget(self.password2)
        fl.addSpacing(8)
        fl.addLayout(row)
        fl.addSpacing(6)
        fl.addWidget(self.footer)

        shell_l.addStretch(1)
        shell_l.addWidget(form, 0, Qt.AlignHCenter)
        shell_l.addStretch(1)

        root.addWidget(shell)


    def _style(self) -> str:
        return """
            QWidget { background: #070A12; color: #EAF2FF; font-family: Inter, Segoe UI, Arial; }
            #Shell {
                border-radius: 26px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0A1023, stop:0.35 #090A12, stop:0.70 #0A0F1E, stop:1 #070A12);
                border: 1px solid rgba(255,255,255,0.06);
            }
            #Glass {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.10);
                border-radius: 22px;
            }
            #Stripe {
                border-radius: 18px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #22D3EE, stop:0.45 #A78BFA, stop:1 #FB7185);
            }
            QLabel#BigTitle { font-size: 30px; font-weight: 800; }
            QLabel#ChipText { font-size: 12px; font-weight: 700; color: rgba(7,10,18,0.92); }

            QLineEdit {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.14);
                border-radius: 14px;
                padding: 12px 12px;
                font-size: 14px;
                color: #EAF2FF;
            }
            QLineEdit:focus { border: 1px solid rgba(34,211,238,0.85); background: rgba(255,255,255,0.08); }

            QPushButton#GlowBtn {
                background: rgba(34,211,238,0.18);
                border: 1px solid rgba(34,211,238,0.55);
                border-radius: 14px;
                padding: 12px;
                font-weight: 800;
                color: #EAF2FF;
                font-size: 14px;
            }
            QPushButton#GlowBtn:hover { background: rgba(34,211,238,0.24); border: 1px solid rgba(34,211,238,0.85); }

            QPushButton#AltBtn {
                background: rgba(167,139,250,0.14);
                border: 1px solid rgba(167,139,250,0.45);
                border-radius: 14px;
                padding: 12px;
                font-weight: 700;
                color: rgba(234,242,255,0.92);
            }
            QPushButton#AltBtn:hover { border: 1px solid rgba(251,113,133,0.65); background: rgba(251,113,133,0.14); }
        """

    def _fmt_backend_msg(self, sc, data) -> str:
        if isinstance(data, dict):
            msg = data.get("error") or data.get("message") or data.get("raw") or str(data)
        else:
            msg = str(data)
        msg = msg if len(msg) <= 1200 else (msg[:1200] + "\n…(truncated)…")
        return f"HTTP {sc}\n{msg}"

    def create_account(self):
        username = self.username.text().strip()
        pw1 = self.password.text()
        pw2 = self.password2.text()

        if pw1 != pw2:
            QMessageBox.warning(self, "Eroare", "Parolele nu coincid.")
            return

        if not username or not pw1:
            QMessageBox.warning(self, "Eroare", "Completează username și parolă.")
            return

        self.btn_create.setEnabled(False)
        self.footer.setText("Registering…")

        try:
          
            sk = SecretKey.random()
            pk = sk.public_key()

            signing_key = SecretKey.random()

            signer = Signer(signing_key)
            vk = signer.verifying_key()

            signing_sk_b64 = base64.b64encode(signing_key.to_secret_bytes()).decode("utf-8")
            vk_b64 = base64.b64encode(bytes(vk)).decode("utf-8")

           
        

            sk_b64 = base64.b64encode(sk.to_secret_bytes()).decode("utf-8")
            pk_b64 = base64.b64encode(bytes(pk)).decode("utf-8")
            vk_b64 = base64.b64encode(bytes(vk)).decode("utf-8")

            keys_dir = Path.cwd() / "drive_keys"
            keys_dir.mkdir(parents=True, exist_ok=True)

            (keys_dir / f"{username}_signing_private.key").write_text(
                signing_sk_b64, encoding="utf-8"
            )
            (keys_dir / f"{username}_umbral_private.key").write_text(sk_b64, encoding="utf-8")
            (keys_dir / f"{username}_umbral_public.key").write_text(pk_b64, encoding="utf-8")

        

        except Exception as e:
            self.btn_create.setEnabled(True)
            self.footer.setText("ECC error.")
            QMessageBox.critical(self, "Eroare ECC", f"Nu am :\n{e}")
            return

        def job():
            return api.post_json("/v1/api/auth/register", {
                "username": username,
                "password": pw1,
                "ecc_public_key": pk_b64,
                "signing_public_key": vk_b64,
                "role": "user"
            })

        j = ApiJob(job)

        self._pending_jobs.append(j)

        def _cleanup_job():
            try:
                self._pending_jobs.remove(j)
            except ValueError:
                pass

        def _ok(res):
            _cleanup_job()
            self._on_register_done_with_keypaths(res, (keys_dir / f"{username}_umbral_private.key"), (keys_dir / f"{username}_umbral_public.key"))

        def _err(msg, tb):
            _cleanup_job()
            self._on_api_error(msg, tb)

        j.signals.ok.connect(_ok)
        j.signals.err.connect(_err)
        pool.start(j)

    def _on_register_done_with_keypaths(self, res, priv_path, pub_path):
        self.btn_create.setEnabled(True)

        sc, data = res
        if sc == 200:
            self.footer.setText("Register OK.")

            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Succes")
            msg.setText("Cont creat cu succes.")
            details = (
                "Cheia privată a fost salvată local.\n\n"
                f"Cheia privată:\n{priv_path}\n\n"
                f"Cheia publică:\n{pub_path}\n\n"
                "Cheia publică a fost trimisă către backend."
            )

            msg.setStyleSheet("QLabel{min-width: 150px; min-height: 50px;}")

            msg.exec()

            self.back()

        else:
            self.footer.setText(f"Register failed.")

            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Eroare")
            msg.setText("Înregistrarea a eșuat.")
            if isinstance(data, dict):
                details = (
                    data.get("error")
                    or data.get("message")
                    or str(data)
                )
            else:
                details = str(data)
            msg.setText(details)
            msg.setStyleSheet("QLabel{min-width: 150px; min-height: 50px;}")
            msg.exec()

    def _on_api_error(self, msg, tb):
        self.btn_create.setEnabled(True)
        self.footer.setText("Error.")
        QMessageBox.critical(self, "API error", f"{msg}\n\n{tb}")

    def back(self):
        self.close()
        self.on_back_to_login()


class LoginGlass(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Proiect • Login")
        self.setFixedSize(1040, 600)

        self.setStyleSheet("""
            QWidget { background: #070A12; color: #EAF2FF; font-family: Inter, Segoe UI, Arial; }

            #Shell {
                border-radius: 26px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0A1023, stop:0.35 #090A12, stop:0.70 #0A0F1E, stop:1 #070A12);
                border: 1px solid rgba(255,255,255,0.06);
            }
            #Glass {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.10);
                border-radius: 22px;
            }
            #Stripe {
                border-radius: 18px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #22D3EE, stop:0.45 #A78BFA, stop:1 #FB7185);
            }

            QLabel#BigTitle { font-size: 30px; font-weight: 800; }
            QLabel#Small    { font-size: 12px; color: rgba(234,242,255,0.72); }
            QLabel#ChipText { font-size: 12px; font-weight: 700; color: rgba(7,10,18,0.92); }

            QLineEdit {
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,255,255,0.14);
                border-radius: 14px;
                padding: 12px 12px;
                font-size: 14px;
                color: #EAF2FF;
            }
            QLineEdit:focus { border: 1px solid rgba(34,211,238,0.85); background: rgba(255,255,255,0.08); }

            QPushButton#GlowBtn {
                background: rgba(34,211,238,0.18);
                border: 1px solid rgba(34,211,238,0.55);
                border-radius: 14px;
                padding: 12px;
                font-weight: 800;
                color: #EAF2FF;
                font-size: 14px;
            }
            QPushButton#GlowBtn:hover { background: rgba(34,211,238,0.24); border: 1px solid rgba(34,211,238,0.85); }

            QPushButton#AltBtn {
                background: rgba(167,139,250,0.14);
                border: 1px solid rgba(167,139,250,0.45);
                border-radius: 14px;
                padding: 12px;
                font-weight: 700;
                color: rgba(234,242,255,0.92);
            }
            QPushButton#AltBtn:hover { border: 1px solid rgba(251,113,133,0.65); background: rgba(251,113,133,0.14); }

            QCheckBox { font-size: 12px; color: rgba(234,242,255,0.75); }
            QCheckBox::indicator {
                width: 18px; height: 18px;
                border-radius: 5px;
                border: 1px solid rgba(255,255,255,0.18);
                background: rgba(255,255,255,0.05);
            }
            QCheckBox::indicator:checked {
                background: rgba(34,211,238,0.75);
                border: 1px solid rgba(34,211,238,0.95);
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)

        shell = QFrame()
        shell.setObjectName("Shell")
        shell_l = QHBoxLayout(shell)
        shell_l.setContentsMargins(18, 18, 18, 18)
        shell_l.setSpacing(18)

        glass = QFrame()
        glass.setObjectName("Glass")
        glass.setFixedWidth(500)
        gl = QVBoxLayout(glass)
        gl.setContentsMargins(22, 22, 22, 22)
        gl.setSpacing(14)

        chip_row = QHBoxLayout()


        
        chip = QFrame()
        chip.setFixedSize(450, 450)
        chip.setStyleSheet("""
        QFrame {
            background: rgba(10,16,35,0.75);
            border: 1px solid rgba(34,211,238,0.35);
            border-radius: 22px;
        }
        """)

        chip_l = QVBoxLayout(chip)
        chip_l.setContentsMargins(22, 22, 22, 18)
        chip_l.setSpacing(14)

        lock_icon = QLabel()
        lock_icon.setAlignment(Qt.AlignCenter)
        lock_icon.setPixmap(icon_from_svg(SVG_LOCK, 150).pixmap(150, 150))  
        lock_icon.setStyleSheet("QLabel{background: transparent;}")

        tag = QFrame()
        tag.setStyleSheet("""
        QFrame {
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 999px;
        }
        """)
        tag_l = QHBoxLayout(tag)
        tag_l.setContentsMargins(16, 8, 16, 8)
        tag_l.setSpacing(8)

        subtitle = QLabel("Encrypted. Re-keyed. Secure.")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("""
        QLabel {
            font-size: 15px;
            font-weight: 800;
            letter-spacing: 1.0px;
            color: rgba(234,242,255,0.75);
        }
        """)

        tag_l.addWidget(subtitle)


        underline = QFrame()
        underline.setFixedHeight(4)
        underline.setStyleSheet("""
        QFrame {
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 #22D3EE, stop:0.5 #A78BFA, stop:1 #FB7185);
            border-radius: 2px;
        }
        """)

        chip_l.addStretch(1)
        chip_l.addWidget(lock_icon, 0, Qt.AlignHCenter)
        chip_l.addWidget(tag, 0, Qt.AlignHCenter)
        chip_l.addStretch(1)
        chip_l.addWidget(underline)

        chip_row.addWidget(chip)
        chip_row.addStretch(1)



        gl.addLayout(chip_row)
        gl.addSpacing(6)
        gl.addStretch(1)

    
        form = QFrame()
        form.setStyleSheet("background: transparent;")
        fl = QVBoxLayout(form)
        fl.setContentsMargins(18, 10, 18, 10)
        fl.setSpacing(14)
        fl.addStretch(1)
        title = QLabel("Autentificare")
        title.setStyleSheet("font-size: 22px; font-weight: 800;")

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.addAction(icon_from_svg(SVG_USER, 18), QLineEdit.LeadingPosition)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Parolă")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.addAction(icon_from_svg(SVG_KEY, 18), QLineEdit.LeadingPosition)


        btn_login = QPushButton("Login")
        btn_login.setObjectName("GlowBtn")
        btn_login.clicked.connect(self.do_login)

        btn_signup = QPushButton("Creează cont")
        btn_signup.setObjectName("AltBtn")
        btn_signup.clicked.connect(self.open_signup)

        row = QHBoxLayout()
        row.addWidget(btn_login, 3)
        row.addWidget(btn_signup, 2)


        fl.addWidget(title)
        fl.addSpacing(8)
        fl.addWidget(self.username)
        fl.addWidget(self.password)
        fl.addSpacing(8)
        fl.addLayout(row)
        fl.addStretch(1)

        shell_l.addWidget(glass)
        shell_l.addWidget(form, 1)
        root.addWidget(shell)

    def _show_login_again(self):
        self.username.clear()
        self.password.clear()
        self.show()

    def open_signup(self):
        self.hide()
        self.signup = SignupGlass(on_back_to_login=self.back_from_signup)
        self.signup.show()

    def back_from_signup(self):
        self.show()

    def do_login(self):
        username = self.username.text().strip()
        password = self.password.text()

        if not username or not password:
            QMessageBox.warning(self, "Eroare", "Completează username și parola.")
            return


        def job():
            return api.post_json("/v1/api/auth/login", {
                "username": username,
                "password": password
            })

        j = ApiJob(job)
        j.signals.ok.connect(self._on_login_done)
        j.signals.err.connect(self._on_api_error)
        pool.start(j)

    def _on_login_done(self, res):
        sc, data = res
        if sc == 200:
            STATE.username = data.get("username", "")
            STATE.role = data.get("role", "")
            STATE.ecc_public_key = data.get("ecc_public_key", "")
            STATE.user_id = data.get("id","")  
            

            self.hide()
            self.drive = DriveWindow(on_logout=self._show_login_again)
            self.drive.show()
        else:
            QMessageBox.warning(self, "Eroare", str(data))

    def _on_api_error(self, msg, tb):
        QMessageBox.critical(self, "API error", f"{msg}\n\n{tb}")
        #self.footer.setText("Error.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = LoginGlass()
    w.show()
    sys.exit(app.exec())