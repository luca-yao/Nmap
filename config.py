class Config:
    log_path = '/var/log/nmap/scan.log'
    file_path = '/root/shell.files/test/ip_list.yaml'

class Email:
    MAIL_TO = 'example.mail.com'
    MAIL_FROM = 'example2.mail.com'
    SMTP_SERVER = 'smtp.mail.com'
    SMTP_PORT = 25  # 使用 SSL/TLS 协议时可能需要不同的端口
    SMTP_USERNAME = 'your_email_username'
    SMTP_PASSWORD = 'your_email_password'