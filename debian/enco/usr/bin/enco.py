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
        
        # Dil değişkenlerini başlat
        self.initialize_language_variables()
        
        self.initUI()
        self.update_language()

    def initialize_language_variables(self):
        # Varsayılan olarak Türkçe değerleri ayarla
        self.file_select_error = "Lütfen bir dosya seçin!"
        self.password_length_error = "Parola uzunluğu 4-64 karakter arasında olmalıdır!"
        self.encrypted_file_error = "Lütfen şifrelenmiş bir .enco dosyası seçin!"
        self.encryption_success = "Şifreleme tamamlandı: "
        self.decryption_success = "Çözme tamamlandı: "
        self.error_prefix = "Hata: "
        self.selected_file_text = "Seçilen Dosya: "
        self.about_menu_text = "Hakkında"
        self.language_label_text = "Dil:"

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
        
        language_label = QLabel(self.language_label_text)
        language_label.setStyleSheet("color: #FFD24C;")
        
        language_layout.addWidget(language_label)
        language_layout.addWidget(self.language_combo)
        layout.addLayout(language_layout)
        
        # Logo kısmı
        self.logo_label = QLabel(self)
        pixmap = QPixmap(logo_path)
        scaled_pixmap = pixmap.scaled(80, 80, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.logo_label.setPixmap(scaled_pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setFixedHeight(80)

        

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
            
            # Hata mesajları
            self.file_select_error = "Please select a file!"
            self.password_length_error = "Password length must be 4-64 characters!"
            self.encrypted_file_error = "Please select an encrypted .enco file!"
            self.encryption_success = "Encryption completed: "
            self.decryption_success = "Decryption completed: "
            self.error_prefix = "Error: "
            self.selected_file_text = "Selected File: "
            
            # Menü öğeleri
            self.about_menu_text = "About"
            self.language_label_text = "Language:"
            
        else:
            # Türkçe çeviriler
            self.setWindowTitle("EnCo Dosya Şifrele/Çöz")
            self.label.setText("Dosya seçilmedi.")
            self.encrypt_button.setText("🔒 Dosyayı Şifrele")
            self.decrypt_button.setText("🔑 Dosyayı Çöz")
            self.drop_label.setText("Dosya Sürükle-Bırak")
            self.click_to_select_label.setText("Dosya Seçmek İçin Tıklayınız")
            
            # Hata mesajları
            self.file_select_error = "Lütfen bir dosya seçin!"
            self.password_length_error = "Parola uzunluğu 4-64 karakter arasında olmalıdır!"
            self.encrypted_file_error = "Lütfen şifrelenmiş bir .enco dosyası seçin!"
            self.encryption_success = "Şifreleme tamamlandı: "
            self.decryption_success = "Çözme tamamlandı: "
            self.error_prefix = "Hata: "
            self.selected_file_text = "Seçilen Dosya: "
            
            # Menü öğeleri
            self.about_menu_text = "Hakkında"
            self.language_label_text = "Dil:"

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
            self.label.setText(f"{self.selected_file_text}{os.path.basename(file_path)}")

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
            self.label.setText(self.file_select_error)
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
            
            self.label.setText(f"{self.encryption_success}{os.path.basename(encrypted_path)}")

        except Exception as e:
            error_text = f"{self.error_prefix}{str(e)}"
            self.label.setText(error_text)

    def decrypt_file(self):
        if not self.file_path or not self.file_path.endswith(".enco"):
            self.label.setText(self.encrypted_file_error)
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
            
            self.label.setText(f"{self.decryption_success}{os.path.basename(original_path)}")

        except Exception as e:
            error_text = f"{self.error_prefix}{str(e)}"
            self.label.setText(error_text)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_path = file_path
            self.label.setText(f"{self.selected_file_text}{os.path.basename(file_path)}")
        
    def show_menu(self):
        menu = QMenu(self)
        about_action = QAction(self.about_menu_text, self)
        about_action.triggered.connect(self.show_about)
        menu.addAction(about_action)
        menu.exec(self.menu_button.mapToGlobal(QPoint(0, 0)))

    def show_about(self):
        # Ortak stil tanımlamaları
        dialog = QDialog(self)
        dialog.setFixedSize(500, 500)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #2D2F31;
                color: #FFD24C;
            }
            QLabel {
                color: #FFD24C;
                font-size: 13px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        
        # Logo ekleme
        logo_label = QLabel()
        logo_pixmap = QPixmap(logo_path).scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Başlık
        title_label = QLabel("EnCo " + ("File Encryption Application" if self.current_language == "English" else "Dosya Şifreleme Uygulaması"))
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFD24C;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # İçerik
        if self.current_language == "English":
            content_text = """
            This application allows you to encrypt your files securely.
            
            Developer: ALG Software Inc.
            Website: www.algyzilim.com
            Email: info@algyazilim.com
            
            Developer: Fatih ÖNDER (CekToR)
            Website: www.fatihonder.org.tr
            Email: fatih@algyazilim.com
            
            EnCo Version: 1.0
            © 2024 ALG Software Inc. GNU License.
            ALG Software Supports Migration to Pardus
            """
            dialog.setWindowTitle("About EnCo")
        else:
            content_text = """
            Bu uygulama, dosyalarınızı kriptolayarak güvenli hale getirmenize olanak tanır.
            
            Geliştirici: ALG Yazılım Inc.
            Web Sitesi: www.algyzilim.com
            E-posta: info@algyazilim.com
            
            Geliştirici: Fatih ÖNDER (CekToR)
            Web Sitesi: www.fatihonder.org.tr
            E-posta: fatih@algyazilim.com
            
            EnCo Sürüm: 1.0
            © 2024 ALG Yazılım Inc. GNU Lisansı.
            ALG Yazılım Pardus'a Göç'ü Destekler
            """
            dialog.setWindowTitle("EnCo Hakkında")
        
        content_label = QLabel(content_text.strip())
        content_label.setAlignment(Qt.AlignCenter)
        content_label.setWordWrap(True)
        layout.addWidget(content_label)
        
        dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    if ICON_PATH:
        app.setWindowIcon(QIcon(ICON_PATH))
    window = FileEncryptionApp()
    layout = QVBoxLayout()
    window.show()
    sys.exit(app.exec())