#!/usr/bin/env python3

import base64
import hashlib
import os
import random
import re
import string
import subprocess
import sys
import time
import traceback

openssl_gen_conf_content = '''[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[v3_req]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[req_distinguished_name]
countryName = JP
countryName_default = JP
stateOrProvinceName = Tokyo
stateOrProvinceName_default = Tokyo
localityName = Tokyo
localityName_default = Tokyo
organizationalUnitName = Tokyo
organizationalUnitName_default = Tokyo
commonName_max = 64
commonName = '''
# append domain name and [alt-names] if more than one.

openssl_gen_conf_path = "/app/openssl-gen.conf"
opendkim_conf_keys_path = "/etc/opendkim/keys"
opendkim_signing_table_path = "/etc/opendkim/keys/signing.table"
opendkim_key_table_path = "/etc/opendkim/keys/key.table"
opendkim_trusted_hosts_path = "/etc/opendkim/trusted.hosts"
letsencrypt_live_cert_path = "/etc/letsencrypt/live"
postfix_cert_path = "/etc/postfix/cert/chains.pem"
postfix_virtual_conf_path = "/etc/postfix/virtual"

email_re = re.compile(
  r'''^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$''')

conf_dict = None


def read_conf() -> dict:
    global conf_dict
    if conf_dict != None:
        return conf_dict
    domain = os.environ.get("SMF_DOMAIN","")
    forward_conf = os.environ.get("SMF_CONFIG","")
    my_networks = os.environ.get("SMF_MYNETWORKS","")
    relay_host = os.environ.get("SMF_RELAYHOST","")
    relay_auth = os.environ.get("SMF_RELAYAUTH","")
    forwards_seg1 = forward_conf.split(";")
    forwards = []
    for seg1 in forwards_seg1:
        forwards_seg2 = seg1.strip().split(":")
        if forwards_seg2 == None or len(forwards_seg2) < 2:
            continue
        print(f">>> forward: {forwards_seg2}")
        forward_from = forwards_seg2[0].strip()
        print(f">>> forward from: {forward_from}")
        if email_re.match(forward_from) == None:
            continue
        forward_to = []
        forwards_seg3 = forwards_seg2[1].split("|")
        for seg3 in forwards_seg3:
            seg3_stripped = seg3.strip()
            if email_re.match(seg3_stripped) != None:
                print(f">>> forward to: {seg3_stripped}")
                forward_to.append(seg3_stripped)
            else:
                continue
        forward_from_pwd = None
        if len(forwards_seg2) > 2 and forwards_seg2[2] != None:
            forward_from_pwd = forwards_seg2[2].strip()
        else:
            forward_from_pwd = get_random_string(32)
        print(f"!!! password for {forward_from}: {forward_from_pwd}")
        if len(forward_to) != 0:
            forwards.append({
                "forward_from": forward_from,
                "forward_to": forward_to,
                "forward_from_pwd": forward_from_pwd,
            })

    conf_dict = {
        "domain": domain,
        "my_networks": my_networks,
        "relay_host": relay_host,
        "relay_auth": relay_auth,
        "forwards": forwards
    }
    return conf_dict


def conf_passwords():
    conf = read_conf()
    for fwd in conf["forwards"]:
        os.system(
            f"echo {fwd['forward_from_pwd']} | saslpasswd2 {fwd['forward_from']}")


def conf_forwarding():
    virtual_users, virtual_domains = get_virtual_users_and_domains()
    virtual_txt = "\n".join(virtual_users)
    virtual_txt += "\n"
    for d in virtual_domains:
        virtual_txt += f"@{d} @{d}\n"
    print(f">>> forwarding virutal config:\n{virtual_txt}")
    with open(postfix_virtual_conf_path, "w") as f:
        f.write(virtual_txt)
    virtual_domains_s = " ".join(virtual_domains)
    os.system(f'postconf -e relay_domains="{virtual_domains_s}"')
    os.system(
        f'postconf -e virtual_alias_maps="hash:{postfix_virtual_conf_path}"')
    os.system(f"postmap {postfix_virtual_conf_path}")


def get_virtual_users_and_domains():
    conf = read_conf()
    virtual_users = []
    virtual_domains = []
    for fwd in conf["forwards"]:
        m_from = fwd["forward_from"]
        m_to = fwd["forward_to"]
        user_and_domain = get_user_and_domain_from_email(m_from)
        from_domain = user_and_domain["domain"]
        if from_domain not in virtual_domains:
            virtual_domains.append(from_domain)
        m_to_s = " ".join(m_to)
        virtual_users.append(f"{m_from} {m_to_s}")
    return virtual_users, virtual_domains


def get_hostname():
    hostname_proc = subprocess.run(["hostname"], stdout=subprocess.PIPE)
    return hostname_proc.stdout.decode('utf-8').strip()


def conf_my_networks():
    conf = read_conf()
    domain = conf["domain"].strip()
    if domain == None or domain == "":
        domain = get_hostname()
    my_networks = conf["my_networks"].strip()
    if my_networks != None and my_networks != "":
        os.system(f'postconf -e mynetworks="{my_networks}"')
    os.system(f'postconf -e myhostname="{domain}"')
    os.system(f'postconf -e mydestination="localhost"')
    os.system(f'echo "{domain}" > /etc/mailname')
    os.system(f'echo "{domain}" > /etc/hostname')


def conf_relay():
    conf = read_conf()
    relay_host = conf["relay_host"].strip()
    relay_auth = conf["relay_auth"].strip()
    if relay_host != None and relay_host != "":
        os.system(f'postconf -e relayhost="{relay_host}"')
    else:
        return
    if relay_auth != None and relay_auth != "":
        os.system(
            f'echo "{relay_host}  {relay_auth}" > /etc/postfix/sasl_passwd')
        os.system(f'postmap /etc/postfix/sasl_passwd')
        os.system(f'postconf -e smtp_use_tls=yes')
        os.system(f'postconf -e smtp_sasl_auth_enable=yes')
        os.system(f'postconf -e smtp_sasl_security_options=')
        os.system(
            f'postconf -e smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd')
        os.system(f'postconf -e smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt')


def gen_dkim_trusted_hosts():
    _, domains = get_virtual_users_and_domains()
    hostname = get_hostname()
    trust_hosts_txt = "127.0.0.1\n"
    trust_hosts_txt += "::1\n"
    trust_hosts_txt += "localhost\n"
    trust_hosts_txt += f"{hostname}\n"
    for dm in domains:
        trust_hosts_txt += f"{hostname}.{dm}\n"
        trust_hosts_txt += f"{dm}\n"
    print(f">>> dkim trust hosts:\n{trust_hosts_txt}")
    with open(opendkim_trusted_hosts_path, "w") as f:
        f.write(trust_hosts_txt)


def gen_dkim_key():
    _, domains = get_virtual_users_and_domains()
    signing_table_txt = ""
    key_table_txt = ""
    for dm in domains:
        dm_hash = short_hash(dm)
        signing_table_txt += f"*@{dm} {dm_hash}"
        current_time_epoch = int(time.time())
        key_name = f"{dm}-{current_time_epoch}"
        os.chdir(opendkim_conf_keys_path)
        os.system(
            f"opendkim-genkey -b 2048 -h rsa-sha256 -r -s {key_name} -d {dm} -v")
        with open(os.path.join(opendkim_conf_keys_path, f"{key_name}.txt"), "r") as fdk_txt:
            txt_tmp = fdk_txt.read()
            print(">>> domain[ {dm} ] dkim txt:\n{txt_tmp}")
        key_table_txt += f"{dm_hash}  {dm}:{current_time_epoch}:/etc/opendkim/keys/{key_name}.private"
    print(f">>> dkim signing table:\n{signing_table_txt}")
    print(f">>> dkim key table:\n{key_table_txt}")
    with open(opendkim_signing_table_path, "w") as fsign:
        fsign.write(signing_table_txt)
    with open(opendkim_key_table_path, "a+") as fsign:
        fsign.write(key_table_txt)
    os.system(f"touch {os.path.join(opendkim_conf_keys_path, 'lock')}")

def gen_openssl_cert(domains: list = None) -> bool:
    if domains == None or len(domains) == 0:
        return False
    with open(openssl_gen_conf_path, "w") as f:
        names_conf = openssl_gen_conf_content
        for i, domain in enumerate(domains):
            if i == 0:
                names_conf += f"{domain}\n\n[alt_names]\nDNS.1="
            if i == 1:
                names_conf += f"{domain}\n"
            if i > 1:
                names_conf += f"DNS.{i}={domain}\n"
        print(f">>> openssl conf:\n{names_conf}")
        f.write(names_conf)
    openssl_proc = subprocess.run(["/usr/bin/env",
                                   "bash", "/app/gen-cert-openssl.sh"])
    if openssl_proc.returncode == 0:
        print(">>> openssl ran sucessfully")
    else:
        print("!!! openssl ran failed")
        return False
    return True


def gen_certbot_cert(domains: list = None) -> bool:
    if domains == None or len(domains) == 0:
        return False
    subprocess.run(
        ["rm", "-rf", os.path.join(letsencrypt_live_cert_path, "*")])

    forwards = read_conf()["forwards"]
    if len(forwards) == 0:
      print("!!! no email in forwards, can't finish certbot register")
      return False
    email_reg = forwards[0]["forward_from"]
    print(f">>> use {email_reg} for letsencrypt registration")
    certbot_proc = subprocess.run(["certbot",
                                   "certonly", "--agree-tos", "-n", "-m", email_reg,
                                   "--dns-cloudflare", "--dns-cloudflare-credentials",
                                   "/app/CLOUDFLARE_DNS_API_TOKEN", "-d",
                                   ",".join([s.strip() for s in domains])])
    if certbot_proc.returncode != 0:
        print("!!! certbot ran failed")
        return False
    print(">>> certbot ran successfully")
    os.remove(postfix_cert_path)
    subfolders = [d.path for d in os.scandir(
        letsencrypt_live_cert_path) if d.is_dir()]
    for folder in subfolders:
        privkey_path = os.path.join(folder, "privkey.pem")
        fullchain_cert_path = os.path.join(folder, "fullchain.pem")
        if not os.path.exists(privkey_path) or not os.path.exists(fullchain_cert_path):
            continue
        os.system(f"cat {privkey_path} >> {postfix_cert_path}")
        os.system(f"cat {fullchain_cert_path} >> {postfix_cert_path}")
    return True


def set_perm():
    os.system("chown -R root.postfix /etc/postfix/cert/")
    os.system("chmod -R 750 /etc/postfix/cert/")
    os.system("chmod u=rw,go=r /etc/opendkim.conf")
    os.system("chown -R opendkim:opendkim /etc/opendkim")
    os.system("chmod go-rw /etc/opendkim/keys")
    os.system("chown -R opendkim:postfix /var/spool/postfix/opendkim")
    os.system("chown postfix /etc/sasldb2")
    os.system("chmod 600 /app/CLOUDFLARE_DNS_API_TOKEN")

def get_random_string(length: int = 16) -> str:
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def get_user_and_domain_from_email(email: str = None) -> dict:
    if email_re.match(email) != None:
        arr = email.split("@")
        return dict(
            user=arr[0],
            domain=arr[1],
        )

def short_hash(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:16]

def b64enc_withou_padding(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    elif not isinstance(s, bytes):
        s = str(s).encode("utf-8")
    return base64.urlsafe_b64encode(s).decode('utf-8').rstrip("=")


def b64dec_withou_padding(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def main() -> int:
    try:
        print(">>> start init-config")
        _, virtual_domains = get_virtual_users_and_domains()
        print(f">>> virtual domains: {virtual_domains}")
        if not os.path.exists(postfix_cert_path):
            print(f">>> ENV CLOUDFLARE_DNS_API_TOKEN: {os.environ.get('CLOUDFLARE_DNS_API_TOKEN')}")
            if os.environ.get("CLOUDFLARE_DNS_API_TOKEN") != None \
                and os.environ.get("CLOUDFLARE_DNS_API_TOKEN").strip() != "":
                print(">>> will generate postfix certbot certs")
                if not gen_certbot_cert(virtual_domains):
                    print("!!! generate certbot cert failed")
                    return 1
            else:
                print(">>> will generate postfix openssl certs")
                if not gen_openssl_cert(virtual_domains):
                    print("!!! generate openssl cert failed")
                    return 1

        if not os.path.exists(os.path.join(opendkim_conf_keys_path, "lock")):
            print(">>> will generate dkim key")
            gen_dkim_key()

        print(">>> will generate dkim trusted.hosts")
        gen_dkim_trusted_hosts()
        print(">>> will config passwords")
        conf_passwords()
        print(">>> will config forwarding")
        conf_forwarding()
        print(">>> will config mynetworks")
        conf_my_networks()
        print(">>> will confing relay")
        conf_relay()
        print(">>> will set file permission")
        set_perm()
    except Exception as e:
        print(e)
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
