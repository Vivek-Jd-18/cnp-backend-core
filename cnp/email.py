# Capacity email utilities
# See https://stackoverflow.com/a/20485764 and https://stackoverflow.com/a/43157340 for some info about emails with inline images.

import smtplib
from email.message import EmailMessage
from . import capa_base


def add_email_config(config, defaults={}, logger=None):
    # Only add/process the email config parts.
    # Convert Flask-Mail config and use as defaults.
    if "app" in config:
        if "MAIL_SERVER" in config["app"]:
            defaults["email_host"] = config["app"]["MAIL_SERVER"]
        if "MAIL_PORT" in config["app"]:
            defaults["email_port"] = config["app"]["MAIL_PORT"]
        if "MAIL_USERNAME" in config["app"]:
            defaults["email_username"] = config["app"]["MAIL_USERNAME"]
        if "MAIL_PASSWORD" in config["app"]:
            defaults["email_password"] = config["app"]["MAIL_PASSWORD"]
        if "MAIL_USE_TLS" in config["app"]:
            defaults["email_starttls"] = config["app"]["MAIL_USE_TLS"]
        if "MAIL_USE_SSL" in config["app"]:
            defaults["email_ssl"] = config["app"]["MAIL_USE_SSL"]
    # Actually set the email config.
    capa_base.config_default(config, "email_host", "localhost", defaults)
    capa_base.config_default(config, "email_port", 0, defaults)  # Default of 0 will go to default SMTP port for the set config.
    capa_base.config_default(config, "email_ssl", False, defaults)
    capa_base.config_default(config, "email_starttls", False, defaults)
    capa_base.config_default(config, "email_username", "", defaults)
    capa_base.config_default(config, "email_password", "", defaults)
    return config


def create_message(subject="", sender="", reply_to="", recipients=[], cc=[], bcc=[], body_text="", body_html="", attachments=[], logger=None):
    if not subject:
        raise ValueError("Email subject needs to be set.")
    if not sender:
        raise ValueError("Email sender needs to be set.")
    if type(recipients) == str:
        recipients = [recipients]
    if type(recipients) != list or not len(recipients):
        raise ValueError("Email recipients need to be a list and contain at least one entry.")
    if type(cc) == str:
        cc = [cc]
    if type(cc) != list:
        raise ValueError("Email CC needs to be a list.")
    if type(bcc) == str:
        bcc = [bcc]
    if type(bcc) != list:
        raise ValueError("Email BCC needs to be a list.")
    if type(attachments) != list:
        raise ValueError("Email attachments need to be a list.")

    msg = EmailMessage()
    if body_html or attachments:
        msg.preamble = "Please use a MIME-aware mail reader to read this message.\n"
    msg["Subject"] = subject
    msg["From"] = sender
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["To"] = ', '.join(recipients)
    if cc:
        msg["Cc"] = ', '.join(cc)
    if bcc:
        msg["Bcc"] = ', '.join(bcc)
    if not body_text:
        raise ValueError("There always has to be a text body present for an email.")
    msg.set_content(body_text)
    if body_html:
        # Add the html version.  This converts the message into a multipart/alternative
        # container, with the original text message as the first part and the new html
        # message as the second part.
        msg.add_alternative(body_html, subtype="html")
    if attachments:
        add_attachments(msg, attachments, logger=logger)
    return msg


def add_attachments(msg, attachments, logger=None):
    if type(attachments) != list:
        raise ValueError("Email attachments need to be a list.")
    for attachment in attachments:
        add_attachment(msg, attachment, logger=logger)


def add_attachment(msg, attachment, logger=None):
    if type(attachment) != dict or "file_data" not in attachment:
        raise ValueError("Email attachment needs to be a dict and contain some file data.")
    att_data = None
    att_content = {}
    for key in {"filename", "disposition", "params", "headers"}:
        if key in attachment:
            att_content[key] = attachment[key]
        if "cid" in attachment:
            att_content["cid"] = f"<{attachment['cid']}>"
    if "content_type" in attachment:
        maintype, subtype = attachment["content_type"].split('/', 1)
    else:
        maintype = "application"
        subtype = "octet-stream"
    if maintype == "text":
        att_content["subtype"] = subtype
        att_data = str(attachment["file_data"])
    elif maintype == "message":
        att_data = str(attachment["file_data"])
    else:
        att_content["maintype"] = maintype
        att_content["subtype"] = subtype
        att_data = bytes(attachment["file_data"])
    already_attached = False
    if "cid" in att_content:
        html_part = None
        for part in msg.walk():
            # We assume that the first HTML or related document is our HTML part.
            if part.get_content_type() in {"text/html", "multipart/related"}:
                html_part = part
                break
        if html_part:
            # Attach to this message part. Also, if this is a pure HTML part, convert it to a multipart/related.
            if html_part.get_content_type() == "text/html":
                html_part.make_related()
            html_part.add_related(att_data, **att_content)
            already_attached = True
    # If there was no CID or the HTML part was not found, attach directly to the message.
    if not already_attached:
        msg.add_attachment(att_data, **att_content)


def send_message(msg, config, logger=None):
    capa_base.log(logger, "debug", "Sending message via %s...", config["email_host"])
    smtp_class = smtplib.SMTP_SSL if config["email_ssl"] else smtplib.SMTP
    with smtp_class(host=config["email_host"], port=config["email_port"]) as smtp:
        if config["email_starttls"]:
            smtp.starttls()
        if config["email_username"] and config["email_password"]:
            smtp.login(config["email_username"], config["email_password"])
        smtp.send_message(msg)
