from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel, QMenu, QInputDialog, QFrame, QDialog
from PyQt6.QtGui import QPixmap, QFont, QAction, QIcon
from PyQt6.QtCore import Qt, QPoint, QEasingCurve, QPropertyAnimation, QRect
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import sys
from PyQt6.QtCore import QDir

logo_path = os.path.join(sys._MEIPASS, 'encolo.png') if hasattr(sys, '_MEIPASS') else 'encolo.png'
ico_path = os.path.join(sys._MEIPASS, 'encolo.png') if hasattr(sys, '_MEIPASS') else 'encolo.png'

SALT = b'some_salt_value'  # Şifre türetmek için sabit bir salt kullanılıyor.

def get_logo_path():
    # PyInstaller ile paketlendiğinde kullanılan yol
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "encolo.png")
    
    # Sabit bir sistem yolu (ör. /usr/share/)
    elif os.path.exists("/usr/share/icons/hicolor/48x48/apps/encolo.png"):
        return "/usr/share/icons/hicolor/48x48/apps/encolo.png"
    
    # Kullanıcı ev dizinindeki bir yol
    home_dir = os.path.expanduser("~")
    user_logo_path = os.path.join(home_dir, ".enco", "encolo.png")
    if os.path.exists(user_logo_path):
        return user_logo_path

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
        self.setWindowTitle("EnCo Dosya Şifrele/Çöz ")
        self.setWindowIcon(QIcon("encolo.png"))  # Uygulama simgesini ekliyoruz
        self.setGeometry(300, 200, 600, 400)
        self.setFixedSize(350, 450)  # Formu sabit boyutlu hale getiriyoruz.
        self.key = None
        self.setStyleSheet("background-color: #2D2F31; color: #FFD24C;")
        self.setWindowOpacity(0.9)  # %80 şeffaflık
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()

        # Logo kısmı (üst kısmına ekliyoruz)
        self.logo_label = QLabel(self)
        pixmap = QPixmap("encolo.png")  # Logoyu yüklüyoruz (encolo.png dosyasını eklediğinizden emin olun)
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setFixedHeight(100)  # Logo yüksekliğini ayarlıyoruz

        # Alt kısımda diğer UI öğeleri
        self.label = QLabel("Dosya seçilmedi.")
        self.label.setFont(QFont("Arial", 12))
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Buttonları alt alta yerleştiriyoruz.
        button_layout = QVBoxLayout()

        self.encrypt_button = self.create_button("🔒 Dosyayı Şifrele", self.encrypt_file)
        self.decrypt_button = self.create_button("🔑 Dosyayı Çöz", self.decrypt_file)
       # self.file_button = self.create_button("📃 Dosya Seç", self.select_file)

       # button_layout.addWidget(self.file_button)
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)

        # Sürükle ve bırak çerçevesi
        self.drop_frame = QFrame(self)
        self.drop_frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.drop_frame.setStyleSheet("background-color: #FF967615; border-radius: 10px; height: 200px; margin: 20px;")
        self.drop_frame.setAcceptDrops(True)
        self.drop_frame.setObjectName("drop_frame")

        # Sürükle bırak metnini ekliyoruz
        self.drop_label = QLabel("Dosyayı Sürükle Bırak", self.drop_frame)
        self.drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.drop_label.setFont(QFont("Arial", 13))
        self.drop_label.setStyleSheet("color: white;")

        # "Dosya Seçmek İçin Tıklayınız." yazısını ekliyoruz
        self.click_to_select_label = QLabel("Dosya Seçmek İçin Tıklayınız.", self.drop_frame)
        self.click_to_select_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.click_to_select_label.setFont(QFont("Arial", 9))  # Küçük font
        self.click_to_select_label.setStyleSheet("color: #A9A9A9;")  # Gri renk

        # Sürükle-bırak alanını merkezi hale getiriyoruz
        self.drop_frame.setLayout(QVBoxLayout())
        self.drop_frame.layout().addWidget(self.drop_label)
        self.drop_frame.layout().addWidget(self.click_to_select_label)  # Alt yazıyı ekliyoruz
        self.drop_frame.layout().setContentsMargins(0, 0, 0, 0)

        # Layout'a ekliyoruz
        layout.addWidget(self.logo_label)  # Logo ekleniyor
        layout.addWidget(self.label)
        layout.addWidget(self.drop_frame)
        layout.addLayout(button_layout)

        self.central_widget.setLayout(layout)

        # Menü butonu
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

        # Sürükle bırak kısmına tıklanabilirlik ekliyoruz
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

        # Hover animasyonu
        button.setStyleSheet("""
            QPushButton {
                background-color: #FFA6841E;
                color: #2D2F31;
                font-size: 14px;
                border-radius: 10px;
                padding: 10px;
                margin: 10px;
                width: 200px;
            }
            QPushButton:hover {
                background-color: #FFB300;
                transition: all 0.3s;
            }
        """)

        # Animasyon: butonların büyümesi
        self.animate_button(button)
        
        return button

    def animate_button(self, button):
        animation = QPropertyAnimation(button, b"geometry")
        animation.setDuration(300)
        animation.setStartValue(button.geometry())
        animation.setEndValue(QRect(button.x() - 5, button.y() - 5, button.width() + 10, button.height() + 10))
        animation.setEasingCurve(QEasingCurve.Type.OutBounce)
        animation.start()

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Bir dosya seçin")
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Seçilen Dosya: {os.path.basename(file_path)}")

    def on_drop_frame_clicked(self, event):
        """Sürükle bırak alanına tıklandığında dosya seçimi açılmasını sağlıyor."""
        self.select_file()

    def ask_password(self) -> str:
        """Kullanıcıdan bir şifre girmesini ister."""
        password, ok = QInputDialog.getText(self, "Şifre Girin", "Şifre (4-64 karakter):")
        if ok and 4 <= len(password) <= 64:
            return password
        elif ok:
            self.label.setText("Şifre uzunluğu 4-64 karakter arasında olmalıdır!")
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
            encrypted_path = f"{self.file_path}.alg"

            with open(encrypted_path, "wb") as file:
                file.write(encrypted_data)

            os.remove(self.file_path)
            self.file_path = encrypted_path
            self.label.setText(f"Şifreleme tamamlandı: {os.path.basename(encrypted_path)}")

        except Exception as e:
            self.label.setText(f"Hata: {str(e)}")

    def decrypt_file(self):
        if not self.file_path or not self.file_path.endswith(".alg"):
            self.label.setText("Lütfen bir şifrelenmiş dosya seçin!")
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
            original_path = self.file_path.rsplit(".alg", 1)[0]

            with open(original_path, "wb") as file:
                file.write(decrypted_data)

            os.remove(self.file_path)
            self.file_path = original_path
            self.label.setText(f"Çözme tamamlandı: {os.path.basename(original_path)}")

        except Exception as e:
            self.label.setText(f"Hata: {str(e)}")

    def dragEnterEvent(self, event):
        """Sürükle bırak işlemi için gerekli olan fonksiyon."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        """Sürükle bırak işlemi gerçekleştiğinde dosya yolu alır."""
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
            "EnCo Dosya Şifreleme Uygulaması\n\n"
            "Bu uygulama, dosyalarınızı güvenli bir şekilde şifreleyip, şifrelerini çözmenizi sağlar.\n"
            "Kullanıcı dostu arayüzü ile dosyalarınızı kolayca yönetebilirsiniz. \n"
            "ALG Yazılım Inc.© EnCo Tüm Hakları Saklıdır. Kullanımı ve Dağıtımı Serbesttir. Değişiklik Yapılamaz! \n"
            "www.algyazilim.com | info@algyazilim.com \n"
            "Geliştirici: Fatih ÖNDER (cektor) | fatih@algyazilim.com | https://github.com/cektor"
        )
        self.show_about_dialog(about_text)

    def show_about_dialog(self, about_text):
        about_dialog = QDialog(self)
        about_dialog.setWindowTitle("Hakkında")
        about_dialog.setWindowIcon(QIcon("encolo.png"))  # Hakkında penceresi simgesi ekleniyor
        about_dialog.setGeometry(200, 200, 300, 200)

        layout = QVBoxLayout()

        about_label = QLabel(about_text)
        layout.addWidget(about_label)

        close_button = QPushButton("Kapat")
        close_button.clicked.connect(about_dialog.close)
        layout.addWidget(close_button)

        about_dialog.setLayout(layout)
        about_dialog.exec()  # QDialog için exec() kullanılabilir


if __name__ == "__main__":
    app = QApplication([])
    window = FileEncryptionApp()
    window.show()
    app.exec()
