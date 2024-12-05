from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, 
                             QFileDialog, QLabel, QMenu, QInputDialog, QFrame, QDialog, 
                             QAction, QComboBox, QHBoxLayout, QVBoxLayout, QSpacerItem, QSizePolicy, QVBoxLayout)
from PyQt5.QtGui import QPixmap, QFont, QIcon
from PyQt5.QtCore import Qt, QPoint, QUrl, QMimeData, QSettings
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import sys

SALT = b'some_salt_value'

def get_logo_path():
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "encolo.png")
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/encolo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/encolo.png"
    home_dir = os.path.expanduser("/usr/share/icons/hicolor/48x48/apps/encolo.png")
    if os.path.exists(home_dir):
        return home_dir
    return "encolo.png"

logo_path = get_logo_path()

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_icon_path():
    """Simge dosyasının yolunu döndürür."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "pasgenlo.png")
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/pasgenlo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/pasgenlo.png"
    return None

LOGO_PATH = get_logo_path()
ICON_PATH = get_icon_path()

class FileEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("ALG Software", "EnCo")
        
        # Dil ayarını yükle
        self.current_language = self.settings.value("language", "Turkish")
        
        self.initUI()
        self.update_language()

    def initUI(self):
        self.setWindowTitle("EnCo Dosya Şifrele/Çöz")
        self.setWindowIcon(QIcon(logo_path))
        self.setFixedSize(350, 550)
        self.key = None
        self.setStyleSheet("background-color: #2D2F31; color: #FFD24C;")
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        # Dil Seçim Bölümü
        language_layout = QHBoxLayout()
        self.language_combo = QComboBox()
        self.language_combo.addItems(["Turkish", "English"])
        self.language_combo.setCurrentText(self.current_language)
        self.language_combo.currentTextChanged.connect(self.change_language)
        
        

        
        language_label = QLabel("Dil / Language:")
        language_label.setStyleSheet("color: #FFD24C;")

        
        
        language_layout.addWidget(language_label)
        language_layout.addWidget(self.language_combo)
        layout.addLayout(language_layout)
        
        
        

        # Logo kısmı
        self.logo_label = QLabel(self)
        pixmap = QPixmap(logo_path)
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setFixedHeight(100)

        

        self.label = QLabel("Dosya seçilmedi.")
        self.label.setFont(QFont("Arial", 12))
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)

        button_layout = QVBoxLayout()
        self.encrypt_button = self.create_button("🔒 Dosyayı Şifrele", self.encrypt_file)
        self.decrypt_button = self.create_button("🔑 Dosyayı Çöz", self.decrypt_file)

        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)

        self.drop_frame = QFrame(self)
        self.drop_frame.setFrameShape(QFrame.StyledPanel)
        self.drop_frame.setStyleSheet("background-color: #a6841e; border-radius: 10px; height: 200px; margin: 20px;")
        self.drop_frame.setAcceptDrops(True)

        self.drop_label = QLabel("Dosya Sürükle-Bırak")
        self.drop_label.setAlignment(Qt.AlignCenter)
        self.drop_label.setFont(QFont("Arial", 13))
        self.drop_label.setStyleSheet("color: white;")
        self.drop_label.setWordWrap(True)

        self.click_to_select_label = QLabel("Dosya Seçmek İçin Tıklayınız.")
        self.click_to_select_label.setAlignment(Qt.AlignCenter)
        self.click_to_select_label.setFont(QFont("Arial", 9))
        self.click_to_select_label.setStyleSheet("color: #A9A9A9;")
        self.click_to_select_label.setWordWrap(True)

        self.drop_frame.setLayout(QVBoxLayout())
        self.drop_frame.layout().addWidget(self.drop_label)
        self.drop_frame.layout().addWidget(self.click_to_select_label)
        self.drop_frame.layout().setContentsMargins(0, 0, 0, 0)

        

        layout.addWidget(self.logo_label)
        layout.addWidget(self.label)
        layout.addWidget(self.drop_frame)
        layout.addLayout(button_layout)

        

        self.central_widget.setLayout(layout)

        
        
        self.menu_button = QPushButton("⋮", self)
        self.menu_button.setStyleSheet(""" 
            font-size: 20px;
            background-color: #2D2F31;
            color: #FFD24C;
            border: none;
            padding: 10px;
        """)
        self.menu_button.setFixedSize(40, 40)
        self.menu_button.clicked.connect(self.show_menu)
        self.menu_button.move(self.width() - 50, 35)

        self.file_path = None
        self.drop_frame.mousePressEvent = self.on_drop_frame_clicked
        
        self.drop_frame.dragEnterEvent = self.dragEnterEvent
        self.drop_frame.dropEvent = self.dropEvent

        

    def change_language(self, lang):
        # Dil ayarını kaydet
        self.settings.setValue("language", lang)
        self.current_language = lang
        
        # Dili güncelle
        self.update_language()

    def update_language(self):
        if self.current_language == "English":
            # İngilizce çeviriler
            self.setWindowTitle("EnCo File Encrypt/Decrypt")
            self.label.setText("No file selected.")
            self.encrypt_button.setText("🔒 Encrypt File")
            self.decrypt_button.setText("🔑 Decrypt File")
            self.drop_label.setText("Drag and Drop File")
            self.click_to_select_label.setText("Click to Select File")
        else:
            # Türkçe çeviriler
            self.setWindowTitle("EnCo Dosya Şifrele/Çöz")
            self.label.setText("Dosya seçilmedi.")
            self.encrypt_button.setText("🔒 Dosyayı Şifrele")
            self.decrypt_button.setText("🔑 Dosyayı Çöz")
            self.drop_label.setText("Dosya Sürükle-Bırak")
            self.click_to_select_label.setText("Dosya Seçmek İçin Tıklayınız.")


       

    def create_button(self, text: str, action):
        button = QPushButton(text)
        button.setStyleSheet(""" 
            background-color: #a6841e;
            color: #2D2F31;
            font-size: 14px;
            border-radius: 10px;
            padding: 10px;
            margin: 10px;
            width: 200px;
        """)
        button.clicked.connect(action)
        button.setFixedHeight(60)
        return button

    def select_file(self):
        file_dialog = QFileDialog()
        dialog_title = "Select a file" if self.current_language == "English" else "Bir dosya seçin"
        file_path, _ = file_dialog.getOpenFileName(self, dialog_title)
        if file_path:
            self.file_path = file_path
            file_text = "Selected File:" if self.current_language == "English" else "Seçilen Dosya:"
            self.label.setText(f"{file_text} {os.path.basename(file_path)}")

    def on_drop_frame_clicked(self, event):
        self.select_file()

    def ask_password(self) -> str:
        if self.current_language == "English":
            title = "Enter Password"
            message = "Password (4-64 characters):"
            length_error = "Password length must be 4-64 characters!"
        else:
            title = "Parola Girin"
            message = "Parola (4-64 karakter):"
            length_error = "Parola uzunluğu 4-64 karakter arasında olmalıdır!"

        password, ok = QInputDialog.getText(self, title, message)
        if ok and 4 <= len(password) <= 64:
            return password
        elif ok:
            self.label.setText(length_error)
        return None

    def encrypt_file(self):
        if not self.file_path:
            error_text = "Please select a file!" if self.current_language == "English" else "Lütfen bir dosya seçin!"
            self.label.setText(error_text)
            return

        password = self.ask_password()
        if not password:
            return

        self.key = derive_key(password)
        cipher = Fernet(self.key)

        try:
            with open(self.file_path, "rb") as file:
                data = file.read()

            encrypted_data = cipher.encrypt(data)
            encrypted_path = f"{self.file_path}.enco"

            with open(encrypted_path, "wb") as file:
                file.write(encrypted_data)

            os.remove(self.file_path)
            self.file_path = encrypted_path
            
            if self.current_language == "English":
                self.label.setText(f"Encryption completed: {os.path.basename(encrypted_path)}")
            else:
                self.label.setText(f"Şifreleme tamamlandı: {os.path.basename(encrypted_path)}")

        except Exception as e:
            error_text = f"Error: {str(e)}" if self.current_language == "English" else f"Hata: {str(e)}"
            self.label.setText(error_text)

    def decrypt_file(self):
        if not self.file_path or not self.file_path.endswith(".enco"):
            if self.current_language == "English":
                error_text = "Please select an encrypted .enco file!"
            else:
                error_text = "Lütfen şifrelenmiş bir .enco dosyası seçin!"
            self.label.setText(error_text)
            return

        password = self.ask_password()
        if not password:
            return

        self.key = derive_key(password)
        cipher = Fernet(self.key)

        try:
            with open(self.file_path, "rb") as file:
                encrypted_data = file.read()

            decrypted_data = cipher.decrypt(encrypted_data)
            original_path = self.file_path.rsplit(".enco", 1)[0]

            with open(original_path, "wb") as file:
                file.write(decrypted_data)

            os.remove(self.file_path)
            self.file_path = original_path
            
            if self.current_language == "English":
                self.label.setText(f"Decryption completed: {os.path.basename(original_path)}")
            else:
                self.label.setText(f"Çözme tamamlandı: {os.path.basename(original_path)}")

        except Exception as e:
            error_text = f"Error: {str(e)}" if self.current_language == "English" else f"Hata: {str(e)}"
            self.label.setText(error_text)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_path = file_path
            
            if self.current_language == "English":
                self.label.setText(f"Selected File: {os.path.basename(file_path)}")
            else:
                self.label.setText(f"Seçilen Dosya: {os.path.basename(file_path)}")
        
    def show_menu(self):
        menu = QMenu(self)
        about_action = QAction("Hakkında" if self.current_language == "Turkish" else "About", self)
        about_action.triggered.connect(self.show_about)
        menu.addAction(about_action)
        menu.exec(self.menu_button.mapToGlobal(QPoint(0, 0)))

    def show_about(self):
        if self.current_language == "English":
            about_text = (
                "\n\n"
                " EnCo File Encryption Application\n\n"
                " This application allows you to encrypt your files securely.\n\n"
                " Developer: ALG Software Inc. | www.algyzilim.com | info@algyazilim.com\n\n"
                " Fatih ÖNDER (CekToR) | www.fatihonder.org.tr | fatih@algyazilim.com\n\n"
                " EnCo All Rights Reserved. 2024 ALG Software Inc\n\n"
                " ALG Software Supports Migration to Pardus\n\n"
                " EnCo Version: 1.0\n\n"
            )
            dialog_title = "About"
        else:
            about_text = (
                "\n\n"
                " EnCo Dosya Şifreleme Uygulaması\n\n"
                " Bu uygulama, dosyalarınızı kriptolayarak güvenli hale getirmenize olanak tanır.\n\n"
                " Geliştirici: ALG Yazılım Inc. | www.algyzilim.com | info@algyazilim.com\n\n"
                " Fatih ÖNDER (CekToR) | wwww.fatihonder.org.tr | fatih@algyazilim.com\n\n"
                " EnCo Tüm Hakları Saklıdır. 2024 ALG Software Inc\n\n"
                " ALG Yazılım Pardus'a Göç'ü Destekler.\n\n"
                " EnCo Sürüm: 1.0\n\n"
           )
        dialog = QDialog(self)
        dialog.setWindowTitle("Hakkında")
        dialog.resize(450, 250)
        label = QLabel(about_text, dialog)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignCenter)
        dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if ICON_PATH:
        app.setWindowIcon(QIcon(ICON_PATH))
    window = FileEncryptionApp()
    layout = QVBoxLayout()
    window.show()
    sys.exit(app.exec())