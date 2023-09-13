import nmap, config, yaml, ipaddress, smtplib
from tabulate import tabulate
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(subject, body):
    try:
        smtp_server = config.Email.SMTP_SERVER
        smtp_port = config.Email.SMTP_PORT
        smtp_username = config.Email.SMTP_USERNAME
        smtp_password = config.Email.SMTP_PASSWORD
        msg = MIMEMultipart()
        msg['From'] = config.Email.MAIL_FROM
        msg['To'] = config.Email.MAIL_TO
        msg['Subject'] = 'Nmap Scan Results'

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        #server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(config.Email.MAIL_FROM, config.Email.MAIL_TO, msg.as_string())
        server.quit()
        print("郵件發送成功")
    except Exception as e:
        print("郵件發送失敗:", str(e))

# 抓取 ip_list.yaml
def load_ip_list(file_path):
    with open(file_path, 'r') as file:
        ip_list = yaml.safe_load(file)

    ips = []
    for item in ip_list:
        if 'IP' in item:
            ips.extend(item['IP'])

    return ips

def scan_tcp_open_ports(IP):
    nm = nmap.PortScanner()
    scan_arguments = '--open'
    nm.scan(IP, arguments=scan_arguments)
    return nm

def format_port_info(nm_result):
    table = []
    for port, port_info in nm_result.items():
        table.append([port, port_info['state'], port_info['name']])
    return table

def log_scan_results(IP, nm):
    result_str = '\n'
    result_str += '\n'
    if 'status' in nm[IP] and nm[IP]['status']['state'] =='up':
        result_str += f'主機名稱 ： {nm[IP].hostname()}\n'
        print(nm[IP])

        if 'tcp' in nm[IP]:
            result_str += 'TCP協議的所有端口:\n'
            table = format_port_info(nm[IP]['tcp'])
            table_str = tabulate(table, headers=['PORT', 'STATE', 'SERVICE'], tablefmt='plain')
            result_str += table_str
        else:
            result_str += '未掃描TCP協議端口\n'
    else:
        result_str += f'主機 {IP} 不存在或狀態為 Down\n'

    return result_str

def write_results_to_file(IP, result_str):
    if result_str:
        current_date = datetime.now(). strftime('%Y-%m-%d')
        output_file = f'scan_result_{current_date}.txt'
        with open(output_file, 'a') as output:
             output.write(result_str)
             output.write('\n')

def main():
    destion_ip_list = load_ip_list(config.Config.file_path)
    email_body = ""

    for ip_input in destion_ip_list:
        if '/' in ip_input:
            ip_network = ipaddress.IPv4Network(ip_input, strict=False)
            for ip in ip_network.hosts():
                IP = str(ip)
                nm = scan_tcp_open_ports(IP)

                if IP in nm.all_hosts():
                   result_str = log_scan_results(IP, nm)
                   write_results_to_file(IP, result_str)
                   email_body += result_str

                else:
                   reuslt_str = f'\n'
                   result_str = f'主機名稱 ： {IP} 不存在或狀態為 Down\n'
                   write_results_to_file(IP, result_str)
                   email_body += result_str

        else:
            IP = ip_input
            nm = scan_tcp_open_ports(IP)

            if 'tcp' in nm[IP]:
                result_str = log_scan_results(IP, nm)
                write_results_to_file(IP, result_str)
                email_body += result_str

            else:
                result_str = f'\n'
                result_str = f'主機名稱 : {IP} 不存在或狀態為 Down\n'
                write_results_to_file(IP, result_str)
                email_body += result_str

    send_email("Nmap Scan Results", email_body)

if __name__ == '__main__':
    main()
