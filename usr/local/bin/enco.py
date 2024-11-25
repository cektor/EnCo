from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel, QMenu, QInputDialog, QFrame, QDialog, QAction
from PyQt5.QtGui import QPixmap, QFont, QIcon
from PyQt5.QtCore import Qt, QPoint, QRect
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import sys

SALT = b'some_salt_value'  # Şifre türetmek için sabit bir salt kullanılıyor.

def get_logo_path():
    # PyInstaller ile paketlendiğinde kullanılan yol
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "encolo.png")
    # Sabit bir sistem yolu
    elif os.path.exists("/usr/share/icons/hicolor/256x256/apps/encolo.png"):
        return "/home/encolo.png"
    home_dir = os.path.expanduser("~/.local/share/encolo.png")
    if os.path.exists(home_dir):
        return home_dir
    # Varsayılan olarak bulunduğu dizindeki encolo.png
    return "encolo.png"

# Logo dosyasının yolu
logo_path = get_logo_path()

def derive_key(password: str) -> bytes:
    """Kullanıcı tarafından girilen şifreye göre bir anahtar türetir."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class FileEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EnCo Dosya Kilitle/Çöz")
        self.setWindowIcon(QIcon(logo_path))  # Uygulama simgesi
        self.setGeometry(300, 200, 600, 400)
        self.setFixedSize(350, 450)
        self.key = None
        self.setStyleSheet("background-color: #2D2F31; color: #FFD24C;")
        self.setWindowOpacity(0.9)  # %80 şeffaflık
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        # Logo kısmı
        self.logo_label = QLabel(self)
        pixmap = QPixmap(logo_path)  # Logoyu yüklüyoruz
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setFixedHeight(100)  # Logo yüksekliği

        self.label = QLabel("Dosya seçilmedi.")
        self.label.setFont(QFont("Arial", 12))
        self.label.setAlignment(Qt.AlignCenter)

        button_layout = QVBoxLayout()
        self.encrypt_button = self.create_button("🔒 Dosyayı Kilitle", self.encrypt_file)
        self.decrypt_button = self.create_button("🔑 Dosyayı Çöz", self.decrypt_file)

        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)

        self.drop_frame = QFrame(self)
        self.drop_frame.setFrameShape(QFrame.StyledPanel)
        self.drop_frame.setStyleSheet("background-color: #FF967615; border-radius: 10px; height: 200px; margin: 20px;")
        self.drop_frame.setAcceptDrops(True)

        self.drop_label = QLabel("Dosyayı Sürükle Bırak", self.drop_frame)
        self.drop_label.setAlignment(Qt.AlignCenter)
        self.drop_label.setFont(QFont("Arial", 13))
        self.drop_label.setStyleSheet("color: white;")

        self.click_to_select_label = QLabel("Dosya Seçmek İçin Tıklayınız.", self.drop_frame)
        self.click_to_select_label.setAlignment(Qt.AlignCenter)
        self.click_to_select_label.setFont(QFont("Arial", 9))
        self.click_to_select_label.setStyleSheet("color: #A9A9A9;")

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
        self.menu_button.move(self.width() - 50, 20)

        self.file_path = None
        self.drop_frame.mousePressEvent = self.on_drop_frame_clicked

    def create_button(self, text: str, action):
        button = QPushButton(text)
        button.setStyleSheet(""" 
            background-color: #FFA6841E;
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
        file_path, _ = file_dialog.getOpenFileName(self, "Bir dosya seçin")
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Seçilen Dosya: {os.path.basename(file_path)}")

    def on_drop_frame_clicked(self, event):
        self.select_file()

    def ask_password(self) -> str:
        password, ok = QInputDialog.getText(self, "Parola Girin", "Parola (4-64 karakter):")
        if ok and 4 <= len(password) <= 64:
            return password
        elif ok:
            self.label.setText("Parola uzunluğu 4-64 karakter arasında olmalıdır!")
        return None

    def encrypt_file(self):
        if not self.file_path:
            self.label.setText("Lütfen bir dosya seçin!")
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
            self.label.setText(f"Kilitleme tamamlandı: {os.path.basename(encrypted_path)}")

        except Exception as e:
            self.label.setText(f"Hata: {str(e)}")

    def decrypt_file(self):
        if not self.file_path or not self.file_path.endswith(".enco"):
            self.label.setText("Lütfen bir kilitlenmiş dosya seçin!")
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
            self.label.setText(f"Çözme tamamlandı: {os.path.basename(original_path)}")

        except Exception as e:
            self.label.setText(f"Hata: {str(e)}")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        file_path = event.mimeData().urls()[0].toLocalFile()
        self.file_path = file_path
        self.label.setText(f"Seçilen Dosya: {os.path.basename(file_path)}")

    def show_menu(self):
        menu = QMenu(self)
        about_action = QAction("Hakkında", self)
        about_action.triggered.connect(self.show_about)
        menu.addAction(about_action)
        menu.exec(self.menu_button.mapToGlobal(QPoint(0, 0)))

    def show_about(self):
        about_text = (
            "\n\n"
            " EnCo Dosya Kilitleme Uygulaması\n\n"
            " Bu uygulama, dosyalarınızı kriptolayarak güvenli hale getirmenize olanak tanır.\n\n"
            " Geliştirici: ALG Yazılım Inc. | www.algyzilim.com | info@algyazilim.com\n\n"
            " Fatih ÖNDER (CekToR) | wwww.fatihonder.org.tr | fatih@algyazilim.com\n\n"
            " EnCo Tüm Hakları Saklıdır. 2024 ALG Software Inc\n\n"
           " \n\n"
            " ALG Yazılım Pardus'a Göç'ü Destekler."
        )

        dialog = QDialog(self)
        dialog.setWindowTitle("Hakkında")
        dialog.resize(520, 250)
        label = QLabel(about_text, dialog)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignCenter)
        dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptionApp()
    window.show()
    sys.exit(app.exec())
